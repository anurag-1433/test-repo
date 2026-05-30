"""
Tenant service — organization and membership management.

Handles tenant CRUD, RBAC enforcement, membership invitations,
and role management per the multi-tenant architecture spec.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import db.models as models

logger = logging.getLogger(__name__)

# Default usage limits for new tenants
DEFAULT_LIMITS = {
    "free": {
        "max_repositories": 5,
        "max_reviews_per_day": 50,
        "max_tokens_per_month": 500_000,
    },
    "team": {
        "max_repositories": 50,
        "max_reviews_per_day": 500,
        "max_tokens_per_month": 5_000_000,
    },
    "enterprise": {
        "max_repositories": -1,   # unlimited
        "max_reviews_per_day": -1,
        "max_tokens_per_month": -1,
    },
}


class TenantService:
    """
    Manages tenants (organizations) and memberships.
    Enforces RBAC for all operations.
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_tenant(self, name: str, creator_user_id: str, plan_type: str = "free") -> Dict:
        """
        Create a new tenant and assign the creator as owner.

        Returns the created tenant dict.
        """
        # creator_user_id is the Supabase JWT sub — match on supabase_user_id, not id
        user_stmt = select(models.User).where(models.User.supabase_user_id == creator_user_id)
        result = await self.db.execute(user_stmt)
        user = result.scalar_one_or_none()

        if not user:
            raise ValueError(
                "User is not registered. Call POST /auth/sync after first login to sync your account."
            )

        # Check if user already owns too many tenants (use app UUID)
        existing_stmt = select(func.count()).select_from(models.Membership).where(
            models.Membership.user_id == user.id,
            models.Membership.role == models.MemberRole.owner,
        )
        existing_result = await self.db.execute(existing_stmt)
        existing = existing_result.scalar_one_or_none()

        if (existing or 0) >= 10:
            raise ValueError("Maximum tenant ownership limit reached")

        # Create tenant
        tenant = models.Tenant(
            name=name,
            plan_type=models.PlanLevel(plan_type),
        )
        self.db.add(tenant)
        await self.db.flush()

        # Create owner membership using app UUID (not Supabase UUID)
        membership = models.Membership(
            tenant_id=tenant.id,
            user_id=user.id,
            role=models.MemberRole.owner,
        )
        self.db.add(membership)
        await self.db.commit()
        await self.db.refresh(tenant)

        return self._serialize_tenant(tenant)

    async def get_tenant(self, tenant_id: str, user_id: str) -> Optional[Dict]:
        """
        Get tenant details. User must be a member.
        """
        await self._assert_membership(self.db, tenant_id, user_id)

        stmt = select(models.Tenant).where(
            models.Tenant.id == tenant_id,
            models.Tenant.deleted_at.is_(None),
        )
        result = await self.db.execute(stmt)
        tenant = result.scalar_one_or_none()

        if not tenant:
            return None

        return self._serialize_tenant(tenant)

    async def list_user_tenants(self, user_id: str) -> List[Dict]:
        """List all tenants a user is a member of."""
        app_user_id = await self._resolve_app_user_id(self.db, user_id)
        if not app_user_id:
            return []
        stmt = select(models.Membership).where(models.Membership.user_id == app_user_id)
        result = await self.db.execute(stmt)
        memberships = result.scalars().all()

        res = []
        for m in memberships:
            t_stmt = select(models.Tenant).where(
                models.Tenant.id == m.tenant_id,
                models.Tenant.deleted_at.is_(None),
            )
            t_result = await self.db.execute(t_stmt)
            tenant = t_result.scalar_one_or_none()
            if tenant:
                t = self._serialize_tenant(tenant)
                t["role"] = m.role.value if hasattr(m.role, "value") else m.role
                res.append(t)

        return res

    async def update_tenant(self, tenant_id: str, user_id: str, updates: Dict) -> Optional[Dict]:
        """Update tenant settings. Requires owner/admin role."""
        await self._assert_role(self.db, tenant_id, user_id, ["owner", "admin"])

        stmt = select(models.Tenant).where(models.Tenant.id == tenant_id)
        result = await self.db.execute(stmt)
        tenant = result.scalar_one_or_none()

        if not tenant:
            return None

        if "name" in updates:
            tenant.name = updates["name"]

        await self.db.commit()
        await self.db.refresh(tenant)
        return self._serialize_tenant(tenant)

    async def delete_tenant(self, tenant_id: str, user_id: str) -> None:
        """
        Soft-delete a tenant. Owner only.
        Blocked if other members exist or active repositories remain.
        """
        # Check existence before RBAC so nonexistent tenants get 404, not 403
        stmt = select(models.Tenant).where(models.Tenant.id == tenant_id)
        result = await self.db.execute(stmt)
        tenant = result.scalar_one_or_none()
        if not tenant:
            raise ValueError("Tenant not found")

        await self._assert_role(self.db, tenant_id, user_id, ["owner"])

        member_count_stmt = select(func.count()).select_from(models.Membership).where(
            models.Membership.tenant_id == tenant_id
        )
        member_count = await self.db.scalar(member_count_stmt)
        if (member_count or 0) > 1:
            raise ValueError("Remove all members before deleting the organization")

        repo_count_stmt = select(func.count()).select_from(models.Repository).where(
            models.Repository.tenant_id == tenant_id,
            models.Repository.deleted_at.is_(None),
        )
        repo_count = await self.db.scalar(repo_count_stmt)
        if (repo_count or 0) > 0:
            raise ValueError("Delete all repositories before deleting the organization")

        tenant.deleted_at = datetime.now(timezone.utc)
        await self.db.commit()

    # -------------------------------------------------------
    # MEMBERSHIP MANAGEMENT
    # -------------------------------------------------------

    async def list_members(self, tenant_id: str, user_id: str) -> List[Dict]:
        """List tenant members with user details. Visible to all members."""
        await self._assert_membership(self.db, tenant_id, user_id)

        stmt = select(models.Membership).where(models.Membership.tenant_id == tenant_id)
        result = await self.db.execute(stmt)
        memberships = result.scalars().all()

        out = []
        for m in memberships:
            u_stmt = select(models.User).where(models.User.id == m.user_id)
            u_result = await self.db.execute(u_stmt)
            user_obj = u_result.scalar_one_or_none()
            out.append(self._serialize_membership(m, user_obj))
        return out

    async def add_member(self, tenant_id: str, actor_user_id: str, target_user_id: str, role: str = "member") -> Dict:
        """Add a member to the tenant. Requires owner/admin."""
        if role not in ("admin", "member", "viewer"):
            raise ValueError(f"Invalid role: {role}")

        await self._assert_role(self.db, tenant_id, actor_user_id, ["owner", "admin"])

        # Ensure user exists
        u_stmt = select(models.User).where(models.User.id == target_user_id)
        u_result = await self.db.execute(u_stmt)
        target_user = u_result.scalar_one_or_none()
        
        if not target_user:
            raise ValueError(
                f"User {target_user_id} is not registered. "
                "They must log in and call POST /auth/sync before being added."
            )

        # Check not already a member
        m_stmt = select(models.Membership).where(
            models.Membership.tenant_id == tenant_id,
            models.Membership.user_id == target_user_id,
        )
        m_result = await self.db.execute(m_stmt)
        existing = m_result.scalar_one_or_none()

        if existing:
            raise ValueError("User is already a member of this tenant")

        membership = models.Membership(
            tenant_id=tenant_id,
            user_id=target_user_id,
            role=models.MemberRole(role),
        )
        self.db.add(membership)
        await self.db.commit()
        await self.db.refresh(membership)
        return self._serialize_membership(membership, None)

    async def update_member_role(
        self, tenant_id: str, actor_user_id: str, target_user_id: str, new_role: str
    ) -> Dict:
        """Update a member's role. Owner-only for promoting to admin."""
        # Only owners can promote to admin
        required_roles = ["owner"] if new_role == "admin" else ["owner", "admin"]
        await self._assert_role(self.db, tenant_id, actor_user_id, required_roles)

        m_stmt = select(models.Membership).where(
            models.Membership.tenant_id == tenant_id,
            models.Membership.user_id == target_user_id,
        )
        m_result = await self.db.execute(m_stmt)
        membership = m_result.scalar_one_or_none()

        if not membership:
            raise ValueError("Member not found")

        current_role = membership.role.value if hasattr(membership.role, "value") else membership.role
        if current_role == "owner":
            raise ValueError("Cannot change owner role")

        membership.role = models.MemberRole(new_role)
        await self.db.commit()
        await self.db.refresh(membership)
        return self._serialize_membership(membership, None)

    async def remove_member(
        self, tenant_id: str, actor_user_id: str, target_user_id: str
    ):
        """Remove a member. Owners cannot be removed."""
        await self._assert_role(self.db, tenant_id, actor_user_id, ["owner", "admin"])

        m_stmt = select(models.Membership).where(
            models.Membership.tenant_id == tenant_id,
            models.Membership.user_id == target_user_id,
        )
        m_result = await self.db.execute(m_stmt)
        membership = m_result.scalar_one_or_none()

        if not membership:
            raise ValueError("Member not found")

        current_role = membership.role.value if hasattr(membership.role, "value") else membership.role
        if current_role == "owner":
            raise ValueError("Cannot remove tenant owner")

        await self.db.delete(membership)
        await self.db.commit()

    # -------------------------------------------------------
    # RBAC ENFORCEMENT
    # -------------------------------------------------------

    async def _resolve_app_user_id(self, db: AsyncSession, supabase_uid: str) -> str | None:
        """Resolve a Supabase JWT sub to the app's users.id (internal UUID).

        Membership.user_id stores the app UUID (users.id), but callers receive
        the Supabase JWT 'sub' stored in users.supabase_user_id. This helper
        bridges the two identity spaces.
        """
        stmt = select(models.User.id).where(
            models.User.supabase_user_id == str(supabase_uid)
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    async def _assert_membership(self, db: AsyncSession, tenant_id: str, user_id: str):
        """Raise if user is not a member of the tenant."""
        app_user_id = await self._resolve_app_user_id(db, user_id)
        if not app_user_id:
            raise PermissionError("User not found — call POST /auth/sync first")

        stmt = select(models.Membership).where(
            models.Membership.tenant_id == tenant_id,
            models.Membership.user_id == app_user_id,
        )
        result = await db.execute(stmt)
        membership = result.scalar_one_or_none()

        if not membership:
            raise PermissionError("User is not a member of this tenant")

    async def _assert_role(
        self, db: AsyncSession, tenant_id: str, user_id: str, allowed_roles: List[str]
    ):
        """Raise if user does not have one of the required roles."""
        app_user_id = await self._resolve_app_user_id(db, user_id)
        if not app_user_id:
            raise PermissionError("User not found — call POST /auth/sync first")

        stmt = select(models.Membership).where(
            models.Membership.tenant_id == tenant_id,
            models.Membership.user_id == app_user_id,
        )
        result = await db.execute(stmt)
        membership = result.scalar_one_or_none()

        if not membership:
            raise PermissionError("User is not a member of this tenant")

        current_role = membership.role.value if hasattr(membership.role, "value") else membership.role
        if current_role not in allowed_roles:
            raise PermissionError(
                f"Requires role {allowed_roles}, user has '{current_role}'"
            )

    # -------------------------------------------------------
    # SERIALIZATION
    # -------------------------------------------------------

    def _serialize_tenant(self, tenant) -> Dict:
        pt = tenant.plan_type.value if hasattr(tenant.plan_type, "value") else getattr(tenant, "plan_type", "free")
        limits = DEFAULT_LIMITS.get(pt, DEFAULT_LIMITS["free"])
        return {
            "id": str(tenant.id),
            "name": tenant.name,
            "plan_type": pt,
            "limits": limits,
            "created_at": tenant.created_at.isoformat() if tenant.created_at else None,
        }

    def _serialize_membership(self, m, user=None) -> Dict:
        return {
            "user_id": str(m.user_id),
            "tenant_id": str(m.tenant_id),
            "role": m.role.value if hasattr(m.role, "value") else m.role,
            "joined_at": m.joined_at.isoformat() if hasattr(m, "joined_at") and m.joined_at else None,
            "email": user.email if user else None,
            "first_name": user.first_name if user else None,
            "last_name": user.last_name if user else None,
            "github_username": user.github_username if user else None,
            "avatar_url": user.avatar_url if user else None,
        }

