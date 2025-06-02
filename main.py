#from pipeline import Pipe as pp
import os
from AES256GCM import *
import hashlib
import io
import zipfile
import json
import gen_rndstring
import sys

def compress(binary_data):
    # メモリ上のバッファを作成
    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # "file.bin"という名前でバイナリデータを書き込む
        zf.writestr("file.bin", binary_data)

    # ZIPデータはzip_buffer.getvalue()で取得できる
    result_zip_data = zip_buffer.getvalue()
    return result_zip_data
def traverse_iterative(start_paths=[os.getcwd()]):
    """
    ディレクトリを再帰的に走査し、ファイルとディレクトリのパスをyieldします。
    非再帰的なアプローチ（スタックを使用）なので、RecursionErrorの心配がありません。
    """
    # 探索対象のパスを保持するスタック（リスト）
    # 初期値として、指定された開始パスを追加
    # os.curdir は '.' を意味します
    stack = [os.path.abspath(p) for p in start_paths] # 絶対パスに変換すると安全

    while stack:
        current_path = stack.pop() # スタックから一つパスを取り出す

        if not os.path.exists(current_path):
            continue # パスが存在しない場合はスキップ

        if os.path.isdir(current_path):
            yield current_path # ディレクトリ自体をyield

            try:
                # ディレクトリ内のエントリを逆順でスタックに追加
                # これにより、スタックから取り出すときに「正しい順序」になる
                for entry_name in reversed(os.listdir(current_path)):
                    full_path = os.path.join(current_path, entry_name)
                    stack.append(full_path)
            except OSError:
                # 権限エラーなど
                pass
        else:
            yield current_path # ファイルをyield
def compute_sha256(text: str) -> str:
    # 文字列をUTF-8にエンコードしてSHA-256ハッシュ値を計算
    return hashlib.sha256(text).hexdigest()

def jsonl_write(line,fname="dirinfo.json"):
    with open(fname,"a") as h:
        h.write(json.dumps(line)+"\n")



##暗号化部分
def encrypt(file_path,output_dir,password,master_mode=False):
    base_db={}
    filepath=file_path.split("/")
    filename=filepath[-1]
    base_db["name"]=filename
    base_db["path"]=filepath[:-1]
    base_db["chunkpath"]=output_dir
    chunkrnd=os.urandom(16)
    chunkbase=compute_sha256(chunkrnd+filename.encode("utf-8")+chunkrnd)
    
    #ソルトはbasekeyの生成に必要なのでパスワードと一緒に保存する必要がある
    base_salt = get_random_bytes(AES.block_size)
    base_db["base_salt"]=base_salt.hex()
    base_key = derive_key(password, base_salt)
    chunk_size = 1024*1024*50 # 50MB ごとのチャンク
    encrypted_chunk_filenames = []
    chunk_index = 0

    with open(file_path, 'rb') as f_orig:
        
        while True:
            
            chunk = f_orig.read(chunk_size)
            #ここで先にzip圧縮を追加する
            #hashのチェック追加(同一なら処理を回避できるし改ざんされてないかのチェックもできる？)
            if not chunk:
                break
            
            encrypted_data_block = encrypt_chunk(chunk, base_key, chunk_index, file_path)
            
            # 各チャンクを独立したファイルとして保存
            nfname=f"{chunkbase}_{chunk_index:05d}"
            fname=compute_sha256(nfname.encode("utf-8"))
            if master_mode:
                fname="masterkey"
            chunk_filename = os.path.join(output_dir, f"{fname}.enc")
            with open(chunk_filename, 'wb') as f_chunk:
                f_chunk.write(encrypted_data_block)
            if master_mode:
                return base_salt.hex()
            else:
                chunkdb=base_db.copy()
                chunkdb["chunk_id"]=chunk_index
                chunkdb["chunk_name"]=chunk_filename
                chunkdb["password"]=password
                jsonl_write(chunkdb)
                chunk_index += 1

    return 0


###復号
def decrypt(chunk_list,decrypted_file_path,password,base_salt):
    #ソルトはbasekeyの生成に必要なのでパスワードと一緒に保存する必要がある
    base_salt=bytes.fromhex(base_salt)
    base_key = derive_key(password, base_salt)


    #decrypted_file_path = "reconstructed_document.txt"
    #password = "MySecurePasswordForChunks!"
      # --- 復号化フェーズ ---
    reconstructed_data = b""
    
    for line in chunk_list:
        i=line["chunk_id"]
        chunk_filename=line["chunk_name"]
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



# --- ここから復号関連の関数を追加 ---
def decrypt_master_key_file(encrypted_master_file_path, master_password, master_salt_hex):
    """
    マスターキーファイル (暗号化された dirinfo.jsonl) を復号する。
    """
    master_salt = bytes.fromhex(master_salt_hex)
    master_key = derive_key(master_password, master_salt) # AES256GCM.py より

    with open(encrypted_master_file_path, 'rb') as f:
        encrypted_data_block = f.read()

    try:
        # decrypt_chunk は (plaintext, associated_data) を返す
        decrypted_jsonl_data, _ = decrypt_chunk(encrypted_data_block, master_key)
        return decrypted_jsonl_data.decode('utf-8') # バイト列を文字列に変換
    except ValueError as e:
        print(f"マスターキーファイルの復号に失敗しました: {e}")
        return None

def restore_directory_structure(output_base_dir, dir_info_jsonl_content):
    """
    dirinfo.jsonl の内容に基づいてディレクトリ構造とファイルを復元する。
    ファイルごとのパスワードは dir_info_jsonl_content から取得する。
    """
    if not os.path.exists(output_base_dir):
        os.makedirs(output_base_dir)
        print(f"復元先ベースディレクトリを作成しました: {output_base_dir}")

    files_to_reconstruct = {}
    for line_str in dir_info_jsonl_content.strip().split('\n'):
        if not line_str:
            continue
        try:
            record = json.loads(line_str)
            # 元のファイルパスを復元するためのキーを生成
            original_file_key = (tuple(record["path"]), record["name"])

            if original_file_key not in files_to_reconstruct:
                files_to_reconstruct[original_file_key] = {
                    "base_salt": record["base_salt"],
                    "password": record["password"], # dirinfo.json に保存されたパスワード
                    "chunks": [],
                    "original_path_list": record["path"],
                    "original_filename": record["name"],
                    "chunk_base_path": record["chunkpath"]
                }
            files_to_reconstruct[original_file_key]["chunks"].append({
                "id": record["chunk_id"],
                "name": record["chunk_name"] # chunk_name はフルパスのはず
            })
        except json.JSONDecodeError:
            print(f"警告: JSONLの行の解析に失敗しました: {line_str}")
            continue
        except KeyError as e:
            print(f"警告: JSONLのレコードに必要なキー ({e}) がありません: {record}")
            continue

    for original_file_key, data in files_to_reconstruct.items():
        original_path_list = data["original_path_list"]
        original_filename = data["original_filename"]
        
        current_output_dir = os.path.join(output_base_dir, *original_path_list)
        if not os.path.exists(current_output_dir):
            os.makedirs(current_output_dir)
        
        decrypted_file_path = os.path.join(current_output_dir, original_filename)
        
        file_specific_password = data.get("password")
        if not file_specific_password:
            print(f"警告: ファイル {os.path.join(*original_path_list, original_filename)} のパスワードがJSONLレコード内に見つかりません。スキップします。")
            continue

        base_salt_hex = data["base_salt"]
        sorted_chunks_info = sorted(data["chunks"], key=lambda c: c["id"])
        
        chunk_list_for_decrypt = []
        for chunk_info in sorted_chunks_info:
            chunk_list_for_decrypt.append({
                "chunk_id": chunk_info["id"],
                "chunk_name": chunk_info["name"]
            })

        print(f"ファイルを復元中: {decrypted_file_path}")
        try:
            # main.py にある既存の decrypt 関数を呼び出す
            decrypt(chunk_list_for_decrypt, decrypted_file_path, file_specific_password, base_salt_hex)
            print(f"ファイルが復元されました: {decrypted_file_path}")
        except Exception as e:
            print(f"ファイル {decrypted_file_path} の復元中にエラーが発生しました: {e}")

def main_decrypt_process(master_password_input, restoration_output_dir, encrypted_files_dir):
    """
    全体の復号処理を実行するメインの関数。
    encrypted_files_dir は masterkey.enc と master_salt.txt があるディレクトリ。
    """
    encrypted_master_file = os.path.join(encrypted_files_dir, "masterkey.enc")
    master_salt_file = os.path.join(encrypted_files_dir, "master_salt.txt")

    if not os.path.exists(encrypted_master_file):
        print(f"エラー: 暗号化されたマスターファイルが見つかりません: {encrypted_master_file}")
        return
    if not os.path.exists(master_salt_file):
        print(f"エラー: マスターソルトファイルが見つかりません: {master_salt_file}")
        return

    with open(master_salt_file, 'r') as f:
        master_salt_hex = f.read().strip()

    print("マスターキーファイルを復号しています...")
    decrypted_jsonl = decrypt_master_key_file(encrypted_master_file, master_password_input, master_salt_hex)

    if decrypted_jsonl:
        print("ディレクトリ構造とファイルを復元しています...")
        restore_directory_structure(restoration_output_dir, decrypted_jsonl)
        print("復元処理が完了しました。")
    else:
        print("dirinfo.json の復号に失敗したため、処理を中止します。")

# --- ここまで復号関連の関数を追加 ---


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("使用法: python main.py <target_dir/restoration_dir> <output_dir/encrypted_files_dir> <master_password> [mode]")
        print("  mode: 'encrypt' (デフォルト) または 'decrypt'")
        print("  encrypt時: <target_dir> <output_dir> <master_password> encrypt")
        print("  decrypt時: <restoration_dir> <encrypted_files_dir> <master_password> decrypt")
        sys.exit(1)

    # 引数の意味をモードによって明確化
    # arg1: encrypt時は暗号化対象ディレクトリ、decrypt時は復元先ディレクトリ
    # arg2: encrypt時は暗号化ファイルの出力先ディレクトリ、decrypt時は暗号化ファイルが格納されているディレクトリ
    # arg3: マスターパスワード
    # arg4: モード (encrypt/decrypt)

    arg1 = sys.argv[1]
    arg2 = sys.argv[2]
    master_password_arg = sys.argv[3]
    
    mode = "encrypt" # デフォルトは暗号化
    if len(sys.argv) > 4:
        mode = sys.argv[4].lower()

    if mode == "encrypt":
        target_dir_arg = arg1
        output_dir_arg = arg2
        print("--- 暗号化処理開始 ---")
        if not os.path.exists(output_dir_arg):
            os.makedirs(output_dir_arg)
            print(f"出力ディレクトリを作成しました: {output_dir_arg}")

        jsonl_filename_default = "dirinfo.json" # encrypt関数内のデフォルトファイル名
        # dirinfo.json は一時的にカレントディレクトリに作成されるため、そのパスを定義
        temp_jsonl_path = os.path.abspath(jsonl_filename_default)

        if os.path.exists(temp_jsonl_path):
            os.remove(temp_jsonl_path) # 追記モードなので、実行前にカレントの同名ファイルを削除

        # 暗号化対象から除外するフルパスのリスト
        # masterkey.enc と master_salt.txt は output_dir_arg に作られる
        # dirinfo.json はカレントディレクトリに一時的に作られる
        excluded_paths = [
            os.path.abspath(os.path.join(output_dir_arg, "masterkey.enc")),
            os.path.abspath(os.path.join(output_dir_arg, "master_salt.txt")),
            temp_jsonl_path
        ]

        paths_to_encrypt = [
            p for p in traverse_iterative([target_dir_arg]) 
            if os.path.isfile(p) and os.path.abspath(p) not in excluded_paths
        ]
        
        if not paths_to_encrypt:
            print(f"警告: {target_dir_arg} 内に暗号化対象ファイルが見つかりませんでした（除外パスを考慮した後）。")
        else:
            for path in paths_to_encrypt:
                print(f"暗号化中: {path}")
                file_password = gen_rndstring.generate_random_string(120)
                # encrypt関数のjsonl_writeはカレントディレクトリの "dirinfo.json" に書き込む
                encrypt(path, output_dir_arg, file_password) # master_mode はデフォルトで False
        
        if os.path.exists(temp_jsonl_path): # 何かファイルが暗号化され、dirinfo.jsonが生成された場合のみ
            print(f"{temp_jsonl_path} をマスターパスワードで暗号化しています...")
            # 最後にdirinfo.jsonをmaster_passwordで暗号化して終了
            # encrypt関数は file_path として temp_jsonl_path を受け取る
            final_master_salt = encrypt(temp_jsonl_path, output_dir_arg, master_password_arg, True) # master_mode=True
            
            os.remove(temp_jsonl_path) # 元のdirinfo.jsonは削除
            
            # master_salt.txt も output_dir_arg に保存
            master_salt_filepath = os.path.join(output_dir_arg, "master_salt.txt")
            with open(master_salt_filepath, "w") as h:
                h.write(final_master_salt)
            print(f"マスターソルトを {master_salt_filepath} に保存しました。")
            print(f"マスターキーファイルは {os.path.join(output_dir_arg, 'masterkey.enc')} として保存されました。")
        elif paths_to_encrypt: # 暗号化対象パスはあったが、dirinfo.jsonが何らかの理由で生成されなかった場合
             print(f"警告: 暗号化対象ファイルはありましたが、{temp_jsonl_path} が生成されませんでした。マスターキーファイルの作成をスキップします。")
        else: # 暗号化対象が最初からなかった場合
            print("暗号化対象ファイルが見つからなかったため、dirinfo.json およびマスターキーファイルの作成をスキップしました。")
        print("--- 暗号化処理完了 ---")

    elif mode == "decrypt":
        restoration_dir_arg = arg1
        encrypted_files_dir_arg = arg2
        print("\n--- 復号化処理開始 ---")

        # restoration_dir_arg が存在しなければ作成
        if not os.path.exists(restoration_dir_arg):
            os.makedirs(restoration_dir_arg)
            print(f"復元先ディレクトリを作成しました: {restoration_dir_arg}")

        main_decrypt_process(
            master_password_arg,
            restoration_dir_arg,
            encrypted_files_dir_arg # masterkey.enc と master_salt.txt があるディレクトリ
        )
        print("--- 復号化処理完了 ---")
    
    else:
        print(f"エラー: 不明なモード '{mode}'。'encrypt' または 'decrypt' を指定してください。")
        sys.exit(1)