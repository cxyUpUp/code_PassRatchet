import secrets
import string


def generate_password_file():
    # 定义需要的口令长度
    lengths = [8, 16, 32, 64, 128]

    # 字符集
    chars = string.ascii_letters + string.digits + "!@#$%^&*"

    # 生成口令字典
    passwords = {}
    for length in lengths:
        password = ''.join(secrets.choice(chars) for _ in range(length))
        passwords[length] = password

    # 保存到单一文件
    with open('passwords.txt', 'w', encoding='utf-8') as f:
        f.write("口令库 - 按长度调用\n")
        f.write("=" * 40 + "\n\n")

        for length in lengths:
            f.write(f"LENGTH_{length}: {passwords[length]}\n")

    print("口令文件已生成: passwords.txt")
    print("\n生成的口令长度:")
    for length in lengths:
        print(f"  {length}字符: {passwords[length]}")

    return passwords


# 生成口令文件
passwords_dict = generate_password_file()