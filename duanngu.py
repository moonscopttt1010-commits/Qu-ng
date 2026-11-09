
import hashlib
import hmac
import os
import time


# Nhap du lieu va hien thi ky tu
def nhap_hien_chu(prompt):
    return input(prompt)


HASH_ALGORITHMS = {
    "1": ("MD5", "md5"),
    "2": ("SHA-1", "sha1"),
    "3": ("SHA-256", "sha256"),
    "4": ("SHA3-256", "sha3_256"),
}


# 1. Bam van ban
def hash_text(text, algorithm):
    data = text.encode("utf-8")
    return hashlib.new(algorithm, data).hexdigest()


def show_hash():
    print("\n--- BAM VAN BAN ---")
    text = nhap_hien_chu("Nhap van ban can bam: ")

    for name, algorithm in HASH_ALGORITHMS.values():
        start = time.perf_counter()
        digest = hash_text(text, algorithm)
        elapsed = time.perf_counter() - start

        print(f"\n{name}")
        print("Gia tri bam:", digest)
        print("Do dai:", len(digest) * 4, "bit")
        print(f"Thoi gian: {elapsed:.8f} giay")


# 2. Mo phong hien tuong Avalanche
def avalanche_demo():
    print("\n--- HIEN TUONG THAY DOI DAU VAO ---")
    original = nhap_hien_chu("Nhap van ban ban dau: ")
    changed = nhap_hien_chu("Nhap van ban da thay doi: ")

    for name, algorithm in [
        ("SHA-256", "sha256"),
        ("SHA3-256", "sha3_256"),
    ]:
        digest1 = hash_text(original, algorithm)
        digest2 = hash_text(changed, algorithm)

        print(f"\n{name}")
        print("Ban dau :", digest1)
        print("Thay doi:", digest2)
        print(
            "Ket qua :",
            "Giong nhau" if digest1 == digest2 else "Khac nhau"
        )


# 3. Bam tep theo tung khoi
def file_hash(filepath, algorithm="sha256"):
    digest = hashlib.new(algorithm)

    with open(filepath, "rb") as file:
        while True:
            chunk = file.read(4096)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def check_file_integrity():
    print("\n--- KIEM TRA TINH TOAN VEN CUA TEP ---")

    filepath = nhap_hien_chu(
        "Nhap duong dan tep: "
    ).strip().strip('"')

    if not os.path.isfile(filepath):
        print("Khong tim thay tep. Hay kiem tra lai duong dan.")
        return

    digest = file_hash(filepath)
    print("SHA-256 cua tep:", digest)

    expected = nhap_hien_chu(
        "Nhap ma SHA-256 tham chieu (Enter de bo qua): "
    ).strip().lower()

    if not expected:
        print("Da hien thi ma bam. Hay luu de doi chieu sau.")

    elif hmac.compare_digest(digest, expected):
        print("KET LUAN: Ma bam trung khop.")

    else:
        print("KET LUAN: Ma bam khong trung khop; tep co the da thay doi.")


# 4. Tao va xac minh HMAC
def make_hmac():
    print("\n--- HMAC-SHA256 ---")

    message = nhap_hien_chu("Nhap thong diep: ")
    key = nhap_hien_chu("Nhap khoa bi mat: ")

    print("Khoa bi mat vua nhap:", key)

    if not key:
        print("Khoa khong duoc de trong.")
        return

    tag = hmac.new(
        key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    print("Ma HMAC:", tag)

    supplied = nhap_hien_chu(
        "Nhap lai ma HMAC de xac minh (Enter de bo qua): "
    ).strip()

    if supplied:
        if hmac.compare_digest(tag, supplied.lower()):
            print("XAC MINH THANH CONG: HMAC hop le.")
        else:
            print("XAC MINH THAT BAI: HMAC khong khop.")


# 5. Mo phong bao ve mat khau bang PBKDF2
def password_demo():
    print("\n--- MO PHONG BAO VE MAT KHAU ---")

    password = nhap_hien_chu("Tao mat khau: ")
    print("Mat khau vua tao:", password)

    if not password:
        print("Mat khau khong duoc de trong.")
        return

    salt = os.urandom(16)
    iterations = 600_000

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations
    )

    print("\nThong tin luu tru mo phong:")
    print("Salt (hex):", salt.hex())
    print("Gia tri bam mat khau:", derived.hex())
    print("So vong PBKDF2:", iterations)

    candidate = nhap_hien_chu(
        "\nNhap mat khau de dang nhap: "
    )

    print("Mat khau dang nhap vua nhap:", candidate)

    check = hashlib.pbkdf2_hmac(
        "sha256",
        candidate.encode("utf-8"),
        salt,
        iterations
    )

    if hmac.compare_digest(derived, check):
        print("Dang nhap thanh cong.")
    else:
        print("Dang nhap that bai.")


# 6. So sanh cac thuat toan
def compare_algorithms():
    print("\n--- SO SANH CAC THUAT TOAN ---")

    text = nhap_hien_chu("Nhap van ban can so sanh: ")

    print(
        f"\n{'Thuat toan':<12}"
        f"{'Do dai (bit)':<15}"
        f"{'Thoi gian (giay)':<18}"
    )
    print("-" * 45)

    for name, algorithm in HASH_ALGORITHMS.values():
        start = time.perf_counter()
        digest = hash_text(text, algorithm)
        elapsed = time.perf_counter() - start

        print(
            f"{name:<12}"
            f"{len(digest) * 4:<15}"
            f"{elapsed:<18.8f}"
        )

    print("\nThoi gian voi van ban ngan chi mang tinh tham khao.")
    print("Khong danh gia do an toan chi dua vao toc do hoac do dai.")


# Menu chinh
def main():
    while True:
        print("\n" + "=" * 54)
        print("  CHUONG TRINH MO PHONG HAM BAM - HIEN MAT KHAU")
        print("=" * 54)

        print("1. Bam van ban bang MD5, SHA-1, SHA-256, SHA3-256")
        print("2. Mo phong thay doi dau vao va gia tri bam")
        print("3. Kiem tra tinh toan ven cua tep bang SHA-256")
        print("4. Tao va xac minh HMAC-SHA256")
        print("5. Mo phong tao va kiem tra mat khau bang PBKDF2")
        print("6. So sanh do dai va thoi gian cac ham bam")
        print("0. Thoat")

        choice = nhap_hien_chu("Chon chuc nang: ").strip()

        if choice == "1":
            show_hash()

        elif choice == "2":
            avalanche_demo()

        elif choice == "3":
            check_file_integrity()

        elif choice == "4":
            make_hmac()

        elif choice == "5":
            password_demo()

        elif choice == "6":
            compare_algorithms()

        elif choice == "0":
            print("Ket thuc chuong trinh.")
            break

        else:
            print("Lua chon khong hop le. Vui long chon lai.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nDa dung chuong trinh.")
