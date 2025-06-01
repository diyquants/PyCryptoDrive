from pipeline import Pipe as pp
import os
#1.暗号化アルゴリズムの選定->AES256

with open(file,"rb") as h:
	file={}
	while True:
		counter=0
		tmp=h.read(chunk_size)
		if len(tmp)==0:
			break
		else:
			encryption(tmp)
			counter+=1
			file[f"file_{counter}"]={#ディレクトリとかタイムスタンプとか？#}
			
#2.ファイルの分割->情報量最大化->効率を考えて50MB
#3.圧縮アルゴリズムの選定->zstd or lz4
#4.ディレクトリ構造の保管形式(json)と暗号化方式(AES)
#5.フロントエンド開発(HTML+CSS+JS+API)
#Drive>Folder1>Folder2
##File1
##Folder3
#.......->クリックでダウンロードか次のフォルダ展開で
#.......->ディレクトリへのドラッグアンドドロップで"ファイルパスを読み取り上の暗号化プロセスに突っ込む