#from pipeline import Pipe as pp
import os
from AES256GCM import *
import hashlib
import io
import zipfile
import json
import gen_rndstring

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



#テスト
if __name__ == '__main__':
    """
    target_dir,output_dir,passwordは外部から与える
    """
    output_dir="."
    target_dir="."
    master_password="1234"
    paths=[path for path in traverse_iterative(target_dir) if os.path.isfile(path)]
    for path in paths:
        file_password=gen_rndstring.generate_random_string(120)
        encrypt(path,output_dir,file_password)
    
    #最後にdirinfo.jsonをmaster_password(password)で暗号化して終了
    master_salt=encrypt("dirinfo.json",output_dir,master_password,True)
    os.remove("dirinfo.json")#ここは3回のやつに切り替える
    with open("master_salt.txt","w") as h:
        h.write(master_salt)
    

    ##復号化はここから
    #print(decrypt([x for x in data["chunkinfo"]],"./requirements2.txt","1234",data["base_salt"]))
    