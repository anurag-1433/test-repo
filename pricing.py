def apply_discount(original_price, discount_amount):
    # Logic bug: We are adding the discount instead of subtracting it!
    final_price = original_price + discount_amount
    return final_price
