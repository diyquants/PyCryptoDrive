#事前にzip圧縮して容量減らす->main.pyに後で統合
import io
import zipfile

# バイナリデータの例（実際には他の手段で得たバイナリデータを格納）
binary_data = b'\x00\x01\x02\x03\x04\x05'

# メモリ上のバッファを作成
zip_buffer = io.BytesIO()

with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
    # "file.bin"という名前でバイナリデータを書き込む
    zf.writestr("file.bin", binary_data)

# ZIPデータはzip_buffer.getvalue()で取得できる
result_zip_data = zip_buffer.getvalue()

# 必要に応じてファイルに書き出す例
with open("result_in_memory.zip", "wb") as f:
    f.write(result_zip_data)
