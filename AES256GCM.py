from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import scrypt
import os

def encrypt_aes_gcm(plaintext, password, associated_data=b''):
    """
    AES-256-GCM を使用してデータを暗号化します。
    鍵はパスワードから導出し、安全なランダムなノンスを使用します。

    Args:
        plaintext (bytes): 暗号化する平文データ。
        password (str): 鍵を導出するためのパスワード。
        associated_data (bytes, optional): 暗号化されないが認証される関連データ。デフォルトは空のバイト列。

    Returns:
        tuple: (salt, nonce, ciphertext, tag)
    """
    # 鍵導出のためのランダムなソルトを生成 (鍵ストレッチングのため)
    salt = get_random_bytes(AES.block_size) 
    
    # scrypt を使用してパスワードから256ビット (32バイト) の鍵を導出
    # n, r, p はセキュリティパラメータ。強度と処理速度のトレードオフ
    key = scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)

    # AES-GCM オブジェクトを作成
    # nonce は暗号化ごとにユニークで予測不可能なものが必要（PyCryptodomeが自動生成）
    cipher = AES.new(key, AES.MODE_GCM)

    # 関連データを設定（暗号化はされないが、認証の対象となる）
    if associated_data:
        cipher.update(associated_data)

    # 平文を暗号化し、認証タグを生成
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return salt, cipher.nonce, ciphertext, tag

def decrypt_aes_gcm(salt, nonce, ciphertext, tag, password, associated_data=b''):
    """
    AES-256-GCM を使用してデータを復号化します。

    Args:
        salt (bytes): 鍵導出に使用したソルト。
        nonce (bytes): 暗号化に使用したノンス。
        ciphertext (bytes): 暗号文データ。
        tag (bytes): 認証タグ。
        password (str): 鍵を導出するためのパスワード。
        associated_data (bytes, optional): 暗号化されないが認証される関連データ。暗号化時と同じである必要があります。

    Returns:
        bytes: 復号化された平文データ。
    Raises:
        ValueError: 認証に失敗した場合（データが改ざんされた場合など）。
    """
    # 鍵導出のためのソルトとパスワードから鍵を再導出
    key = scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)

    # AES-GCM オブジェクトを復号化モードで作成
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # 関連データを設定（暗号化時と同じ関連データが必要）
    if associated_data:
        cipher.update(associated_data)

    # 暗号文を復号化し、タグを検証
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError:
        raise ValueError("認証に失敗しました。データが改ざんされた可能性があります。")

# --- 使用例 ---
if __name__ == "__main__":
    original_plaintext = b"これはAES-256-GCMで暗号化される非常に機密性の高いメッセージです。"
    user_password = "MyStrongPassword123!"
    
    # 関連データ (例: ファイル名、タイムスタンプなど)
    # これは暗号化されませんが、認証の対象となります。
    # 復号時に同じ関連データが提供されない場合、認証に失敗します。
    aad = b"file_id:document_001;creation_date:2025-06-02"

    print(f"元の平文: {original_plaintext.decode('utf-8')}")
    print(f"関連データ (AAD): {aad.decode('utf-8')}")

    # 暗号化
    try:
        salt, nonce, ciphertext, tag = encrypt_aes_gcm(original_plaintext, user_password, aad)
        print("\n--- 暗号化結果 ---")
        print(f"ソルト (hex): {salt.hex()}")
        print(f"ノンス (hex): {nonce.hex()}")
        print(f"暗号文 (hex): {ciphertext.hex()}")
        print(f"認証タグ (hex): {tag.hex()}")
    except Exception as e:
        print(f"暗号化中にエラーが発生しました: {e}")
        exit()

    # 復号化（正しい鍵と関連データで）
    try:
        decrypted_plaintext = decrypt_aes_gcm(salt, nonce, ciphertext, tag, user_password, aad)
        print("\n--- 復号化結果 ---")
        print(f"復号された平文: {decrypted_plaintext.decode('utf-8')}")
        assert original_plaintext == decrypted_plaintext
        print("平文が一致しました。")
    except ValueError as e:
        print(f"\n復号化エラー: {e}")
    except Exception as e:
        print(f"\n予期せぬエラー: {e}")

    print("\n--- 認証失敗のテスト (関連データ改ざん) ---")
    # 復号化（関連データを改ざんした場合）
    tampered_aad = b"file_id:document_001;creation_date:2025-06-03" # 変更されたAAD
    try:
        print(f"改ざんされた関連データ (AAD): {tampered_aad.decode('utf-8')}")
        decrypt_aes_gcm(salt, nonce, ciphertext, tag, user_password, tampered_aad)
    except ValueError as e:
        print(f"復号化エラー（想定通り）: {e}")

    print("\n--- 認証失敗のテスト (暗号文改ざん) ---")
    # 復号化（暗号文を改ざんした場合）
    tampered_ciphertext = ciphertext[:-5] + b'abcde' # 暗号文の一部を変更
    try:
        print(f"改ざんされた暗号文 (hex): {tampered_ciphertext.hex()}")
        decrypt_aes_gcm(salt, nonce, tampered_ciphertext, tag, user_password, aad)
    except ValueError as e:
        print(f"復号化エラー（想定通り）: {e}")

    print("\n--- 認証失敗のテスト (タグ改ざん) ---")
    # 復号化（タグを改ざんした場合）
    tampered_tag = tag[:-5] + b'abcde' # タグの一部を変更
    try:
        print(f"改ざんされたタグ (hex): {tampered_tag.hex()}")
        decrypt_aes_gcm(salt, nonce, ciphertext, tampered_tag, user_password, aad)
    except ValueError as e:
        print(f"復号化エラー（想定通り）: {e}")
