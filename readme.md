# what to do
### CryptoMatorに不満があるので、Client-Side Crypto Containerを自作する
## 1.暗号化アルゴリズムの選定->AES256GCM
## 2.ファイルの分割->情報量最大化->効率を考えて10-50MB/ユーザ指定
## 3.圧縮アルゴリズムの選定->zstd
## 4.ディレクトリ構造の保管形式(jsonl)と暗号化方式(AES256GCM)
## 5.フロントエンド開発(HTML+CSS+JS+API or Python+HTML+CSS)
    - Drive>Folder1>Folder2
        - File1
        - Folder3
         ->クリックでダウンロードか次のフォルダ展開で
        ->ディレクトリへのドラッグアンドドロップで"ファイルパスを読み取り上の暗号化プロセスに突っ込む
