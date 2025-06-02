from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import scrypt
import os

# 鍵導出のためのパラメータ (本番環境ではより大きなNを推奨)
SCRYPT_N = 2**17
SCRYPT_R = 20
SCRYPT_P = 3

def derive_key(password, salt):
    """パスワードとソルトから鍵を導出します。"""
    return scrypt(password.encode(), salt, 32, N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)

def encrypt_chunk(chunk_data, base_key, chunk_index, original_filepath_hint=None):
    """
    データチャンクをAES-256-GCMで暗号化します。
    各チャンクは独立して暗号化され、固有のノンスとタグを持ちます。
    """
    # 各チャンクごとに新しいランダムなノンスを生成
    nonce = get_random_bytes(AES.block_size) # AES.block_size (16バイト) はGCMのノンスサイズとして一般的
    
    cipher = AES.new(base_key, AES.MODE_GCM, nonce=nonce)

    # 関連データ (AAD) の構築
    # チャンクインデックスと元のファイルパスのヒントをAADに含めることで、
    # 復号時にチャンクが正しい順序で、正しいファイルの一部であることを検証する手助けになる。
    # ただし、これだけではチャンクの欠落や重複を完全に防ぐことはできない。
    aad_parts = [
        b"chunk_index:" + str(chunk_index).encode(),
    ]
    if original_filepath_hint:
        aad_parts.append(b"original_filepath:" + original_filepath_hint.encode())
    
    associated_data = b";".join(aad_parts) # AADはセミコロンで結合
    cipher.update(associated_data)

    ciphertext, tag = cipher.encrypt_and_digest(chunk_data)

    # チャンクごとに保存する情報: ノンス、関連データ、暗号文、タグ
    # 関連データの長さも一緒に保存すると、復号時に便利
    chunk_header = (
        nonce + 
        len(associated_data).to_bytes(4, 'big') + # 4バイトでAADの長さを保存
        associated_data
    )
    
    return chunk_header + ciphertext + tag

def decrypt_chunk(encrypted_chunk_data, base_key):
    """
    暗号化されたデータチャンクをAES-256-GCMで復号します。
    """
    # ヘッダーからノンス、関連データ長、関連データを読み込む
    nonce_size = AES.block_size # 16バイト
    aad_len_size = 4
    tag_size = 16 # GCMタグは通常16バイト

    # データが短すぎる場合はエラー
    if len(encrypted_chunk_data) < nonce_size + aad_len_size + tag_size:
        raise ValueError("暗号化されたチャンクデータが不正です (短すぎます)。")

    nonce = encrypted_chunk_data[0:nonce_size]
    aad_len = int.from_bytes(encrypted_chunk_data[nonce_size : nonce_size + aad_len_size], 'big')
    
    # AADの長さがデータ範囲外の場合もエラー
    if len(encrypted_chunk_data) < nonce_size + aad_len_size + aad_len + tag_size:
        raise ValueError("暗号化されたチャンクデータが不正です (AAD長が不正)。")

    associated_data = encrypted_chunk_data[nonce_size + aad_len_size : nonce_size + aad_len_size + aad_len]
    ciphertext_start_index = nonce_size + aad_len_size + aad_len
    
    ciphertext = encrypted_chunk_data[ciphertext_start_index : -tag_size]
    tag = encrypted_chunk_data[-tag_size:]

    cipher = AES.new(base_key, AES.MODE_GCM, nonce=nonce)
    cipher.update(associated_data)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext, associated_data # 復号された平文とAADを返す
    except ValueError as e:
        raise ValueError(f"チャンクの認証に失敗しました。データが改ざんされた可能性があります: {e}")


