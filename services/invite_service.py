import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import db.models as models
from db.models import InviteStatus, MemberRole
from config.settings import settings
from services.email_service import EmailService

logger = logging.getLogger(__name__)


class InviteService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_invite(
        self,
        tenant_id: str,
        invited_by_user_id: str,
        email: Optional[str] = None,
    ) -> dict:
        db = self.db
        await self._assert_role(db, tenant_id, invited_by_user_id, ["owner", "admin"])
        app_user_id = await self._resolve_app_user_id(db, invited_by_user_id)

        if email:
            stmt = select(models.TenantInvite).where(
                models.TenantInvite.tenant_id == tenant_id,
                models.TenantInvite.email == email,
                models.TenantInvite.status == InviteStatus.pending,
            )
            result = await db.execute(stmt)
            existing = result.scalar_one_or_none()
            if existing:
                raise ValueError("Pending invite already exists for this email")

        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)

        invite = models.TenantInvite(
            tenant_id=tenant_id,
            invited_by=app_user_id,
            email=email,
            token=token,
            status=InviteStatus.pending,
            expires_at=expires_at,
        )
        db.add(invite)
        await db.flush()
        await db.refresh(invite)
        await db.commit()

        if email:
            # Fetch org name
            tenant_stmt = select(models.Tenant).where(models.Tenant.id == tenant_id)
            tenant_result = await db.execute(tenant_stmt)
            tenant = tenant_result.scalar_one_or_none()
            org_name = tenant.name if tenant else "Your organization"

            # Fetch inviter name
            user_stmt = select(models.User).where(models.User.id == app_user_id)
            user_result = await db.execute(user_stmt)
            user = user_result.scalar_one_or_none()
            if user:
                if user.first_name and user.last_name:
                    inviter_name = f"{user.first_name} {user.last_name}"
                elif user.first_name:
                    inviter_name = user.first_name
                elif user.email:
                    inviter_name = user.email
                else:
                    inviter_name = "A team member"
            else:
                inviter_name = "A team member"

            accept_url = f"{settings.FRONTEND_URL}/invite/{token}"
            EmailService().send_invite_email(email, org_name, inviter_name, accept_url)

        return self._serialize_invite(invite)

    async def list_invites(self, tenant_id: str, user_id: str) -> list[dict]:
        db = self.db
        await self._assert_role(db, tenant_id, user_id, ["owner", "admin"])

        now = datetime.now(timezone.utc)
        stmt = select(models.TenantInvite).where(
            models.TenantInvite.tenant_id == tenant_id,
            models.TenantInvite.status == InviteStatus.pending,
            models.TenantInvite.expires_at > now,
        )
        result = await db.execute(stmt)
        invites = result.scalars().all()
        return [self._serialize_invite(inv) for inv in invites]

    async def revoke_invite(self, tenant_id: str, invite_id: str, user_id: str) -> None:
        db = self.db
        await self._assert_role(db, tenant_id, user_id, ["owner", "admin"])

        stmt = select(models.TenantInvite).where(
            models.TenantInvite.id == invite_id,
            models.TenantInvite.tenant_id == tenant_id,
        )
        result = await db.execute(stmt)
        invite = result.scalar_one_or_none()
        if not invite:
            raise ValueError("Invite not found")

        invite.status = InviteStatus.revoked
        await db.commit()

    async def get_invite_preview(self, token: str) -> dict:
        db = self.db
        stmt = select(models.TenantInvite).where(models.TenantInvite.token == token)
        result = await db.execute(stmt)
        invite = result.scalar_one_or_none()
        if not invite:
            raise ValueError("not_found")

        now = datetime.now(timezone.utc)
        current_status = invite.status.value if hasattr(invite.status, "value") else invite.status
        if current_status != "pending" or invite.expires_at <= now:
            raise ValueError("gone")

        tenant_stmt = select(models.Tenant).where(models.Tenant.id == invite.tenant_id)
        tenant_result = await db.execute(tenant_stmt)
        tenant = tenant_result.scalar_one_or_none()
        org_name = tenant.name if tenant else "Unknown organization"

        inviter_name = "A team member"
        if invite.invited_by:
            user_stmt = select(models.User).where(models.User.id == invite.invited_by)
            user_result = await db.execute(user_stmt)
            user = user_result.scalar_one_or_none()
            if user:
                if user.first_name and user.last_name:
                    inviter_name = f"{user.first_name} {user.last_name}"
                elif user.first_name:
                    inviter_name = user.first_name
                elif user.email:
                    inviter_name = user.email

        return {
            "org_name": org_name,
            "inviter_name": inviter_name,
            "expires_at": invite.expires_at.isoformat(),
        }

    async def accept_invite(self, token: str, accepting_user_id: str) -> dict:
        db = self.db
        stmt = select(models.TenantInvite).where(models.TenantInvite.token == token)
        result = await db.execute(stmt)
        invite = result.scalar_one_or_none()
        if not invite:
            raise ValueError("not_found")

        now = datetime.now(timezone.utc)
        current_status = invite.status.value if hasattr(invite.status, "value") else invite.status
        if current_status != "pending" or invite.expires_at <= now:
            raise ValueError("gone")

        accepting_app_user_id = await self._resolve_app_user_id(db, accepting_user_id)
        if not accepting_app_user_id:
            raise ValueError("User not synced")

        membership_stmt = select(models.Membership).where(
            models.Membership.tenant_id == invite.tenant_id,
            models.Membership.user_id == accepting_app_user_id,
        )
        membership_result = await db.execute(membership_stmt)
        existing_membership = membership_result.scalar_one_or_none()
        if existing_membership:
            raise ValueError("already_member")

        membership = models.Membership(
            tenant_id=invite.tenant_id,
            user_id=accepting_app_user_id,
            role=MemberRole.member,
        )
        db.add(membership)

        invite.status = InviteStatus.accepted
        invite.accepted_at = datetime.now(timezone.utc)
        invite.accepted_by = accepting_app_user_id

        await db.commit()

        tenant_stmt = select(models.Tenant).where(models.Tenant.id == invite.tenant_id)
        tenant_result = await db.execute(tenant_stmt)
        tenant = tenant_result.scalar_one_or_none()

        return {
            "tenant_id": str(invite.tenant_id),
            "tenant_name": tenant.name if tenant else None,
        }

    # ---- helpers ----

    async def _resolve_app_user_id(self, db, supabase_uid: str):
        stmt = select(models.User.id).where(models.User.supabase_user_id == str(supabase_uid))
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    async def _assert_role(self, db, tenant_id: str, user_id: str, allowed_roles: list[str]):
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
            raise PermissionError(f"Requires role {allowed_roles}, user has '{current_role}'")

    def _serialize_invite(self, invite) -> dict:
        return {
            "id": str(invite.id),
            "tenant_id": str(invite.tenant_id),
            "invited_by": str(invite.invited_by) if invite.invited_by else None,
            "email": invite.email,
            "token": invite.token,
            "status": invite.status.value if hasattr(invite.status, "value") else invite.status,
            "expires_at": invite.expires_at.isoformat(),
            "created_at": invite.created_at.isoformat() if invite.created_at else None,
            "accepted_at": invite.accepted_at.isoformat() if invite.accepted_at else None,
            "accepted_by": str(invite.accepted_by) if invite.accepted_by else None,
        }
