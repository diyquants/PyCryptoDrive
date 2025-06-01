from pipeline import Pipe as pp
import os
from AES256GCM import *

##暗号化部分
def encrypt(original_file_path,output,password):
    filedb={}
    filedb["name"]=file_path.split("/")[-1]
    filedb["path"]=file_path.split("/")[:-1]
    filedb["chunkpath"]=output_dir
    fildb["chuninfo"]=[]

    
    #ソルトはbasekeyの生成に必要なのでパスワードと一緒に保存する必要がある
    base_salt = get_random_bytes(AES.block_size)
    base_key = derive_key(password, base_salt)
    chunk_size = 1024*1024*5 # 50MB ごとのチャンク
    encrypted_chunk_filenames = []
    chunk_index = 0

    with open(original_file_path, 'rb') as f_orig:
        
        while True:
            chunkdb={}
            chunk = f_orig.read(chunk_size)
            if not chunk:
                break
            
            encrypted_data_block = encrypt_chunk(chunk, base_key, chunk_index, original_file_path)
            
            # 各チャンクを独立したファイルとして保存
            chunk_filename = os.path.join(output_dir, f"chunk_{chunk_index:05d}.enc")
            with open(chunk_filename, 'wb') as f_chunk:
                f_chunk.write(encrypted_data_block)
            
            #encrypted_chunk_filenames.append(chunk_filename)
            chunk_index += 1
            #print(f"チャンク {chunk_index} を暗号化し保存しました。")
            chunkdb["id"]=chunk_index
            chunkdb["chunk_name"]=chunk_filename
            filedb.append(chunkdb)



    
    #print(f"\n{chunk_index} 個のチャンクが暗号化され、'{output_dir}' に保存されました。")
    return filedb


###わからん後で
def decrypt(chunk_list,decrypt_file_path,salt,password):
    #ソルトはbasekeyの生成に必要なのでパスワードと一緒に保存する必要がある
    base_salt = get_random_bytes(AES.block_size)
    base_key = derive_key(password, base_salt)


    #decrypted_file_path = "reconstructed_document.txt"
    #password = "MySecurePasswordForChunks!"
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

#1.暗号化アルゴリズムの選定->AES256			
#2.ファイルの分割->情報量最大化->効率を考えて50MB
#3.圧縮アルゴリズムの選定->zstd or lz4
#4.ディレクトリ構造の保管形式(json)と暗号化方式(AES)
#5.フロントエンド開発(HTML+CSS+JS+API)
#Drive>Folder1>Folder2
##File1
##Folder3
#.......->クリックでダウンロードか次のフォルダ展開で
#.......->ディレクトリへのドラッグアンドドロップで"ファイルパスを読み取り上の暗号化プロセスに突っ込む