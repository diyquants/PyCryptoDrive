import random

# 利用する文字の集合を定義する
digits = "0123456789"
symbols = "!\"#$%&'()~"  # 注意: "（ダブルクォート）が含まれているためエスケープする必要があります
lowercase = "abcdefghijklmnopqrstuvwxyz"
uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# 全ての文字を結合
all_chars = digits + symbols + lowercase + uppercase

def generate_random_string(length):
    # 指定した長さのランダム文字列を生成する
    return ''.join(random.choice(all_chars) for _ in range(length))
