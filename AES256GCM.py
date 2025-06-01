from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import scrypt
import os

# 鍵導出のためのパラメータ (本番環境ではより大きなNを推奨)
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

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

# --- 使用例 ---
if __name__ == "__main__":
    original_file_path = "large_document.txt"
    output_dir = "encrypted_chunks"
    decrypted_file_path = "reconstructed_document.txt"
    password = "MySecurePasswordForChunks!"
    
    # 仮の大きなファイルを作成
    with open(original_file_path, "w", encoding="utf-8") as f:
        f.write("This is a line of text for the large document. " * 100 + "\n")
        f.write("Another line of data. " * 50 + "\n")
        f.write("Final line of content." + "\n")
        for i in range(500): # 1000行のデータを作成
            f.write(f"Line number {i}: This is some arbitrary data to simulate a large file.\n")
    
    os.makedirs(output_dir, exist_ok=True)

    # 鍵は一度生成し、ソルトは安全に保存する必要がある (ここでは簡単のためメモリに保持)
    base_salt = get_random_bytes(AES.block_size)
    base_key = derive_key(password, base_salt)

    print(f"元のファイル: {original_file_path}")
    print(f"暗号化されたチャンクの保存先: {output_dir}")

    # --- 暗号化フェーズ ---
    chunk_size = 1024 # 1KB ごとのチャンク
    encrypted_chunk_filenames = []
    chunk_index = 0

    with open(original_file_path, 'rb') as f_orig:
        while True:
            chunk = f_orig.read(chunk_size)
            if not chunk:
                break
            
            encrypted_data_block = encrypt_chunk(chunk, base_key, chunk_index, original_file_path)
            
            # 各チャンクを独立したファイルとして保存
            chunk_filename = os.path.join(output_dir, f"chunk_{chunk_index:05d}.enc")
            with open(chunk_filename, 'wb') as f_chunk:
                f_chunk.write(encrypted_data_block)
            
            encrypted_chunk_filenames.append(chunk_filename)
            chunk_index += 1
            print(f"チャンク {chunk_index} を暗号化し保存しました。")
    
    print(f"\n{chunk_index} 個のチャンクが暗号化され、'{output_dir}' に保存されました。")

    # --- 復号化フェーズ ---
    print(f"\n暗号化されたチャンクを復号し、'{decrypted_file_path}' に再構築します。")
    reconstructed_data = b""
    
    for i, chunk_filename in enumerate(encrypted_chunk_filenames):
        try:
            with open(chunk_filename, 'rb') as f_chunk:
                encrypted_data_block = f_chunk.read()
            
            decrypted_chunk, aad_from_chunk = decrypt_chunk(encrypted_data_block, base_key)
            
            # AADからチャンクインデックスを検証（オプションだが推奨）
            expected_aad_prefix = b"chunk_index:" + str(i).encode()
            if not aad_from_chunk.startswith(expected_aad_prefix):
                print(f"警告: チャンク {i} のAADが期待値と異なります。改ざんの可能性があります。")
                # 必要に応じてエラーを発生させる
            
            reconstructed_data += decrypted_chunk
            print(f"チャンク {i} を復号しました。")

        except ValueError as e:
            print(f"チャンク {i} の復号に失敗しました: {e}")
            # ここで処理を中断するか、エラーを記録して続行するかを決定
            break # 例としてここで中断
        except Exception as e:
            print(f"チャンク {i} の処理中に予期せぬエラーが発生しました: {e}")
            break

    with open(decrypted_file_path, 'wb') as f_dec:
        f_dec.write(reconstructed_data)

    # 元のファイルと再構築されたファイルを比較して検証
    with open(original_file_path, 'rb') as f_orig:
        original_content = f_orig.read()
    
    if original_content == reconstructed_data:
        print("\n成功: 再構築されたファイルの内容が元のファイルと一致しました！")
    else:
        print("\nエラー: 再構築されたファイルの内容が元のファイルと一致しません。")

    # クリーンアップ
    print("\nクリーンアップ中...")
    os.remove(original_file_path)
    os.remove(decrypted_file_path)
    for f in encrypted_chunk_filenames:
        os.remove(f)
    os.rmdir(output_dir)
    print("完了。")