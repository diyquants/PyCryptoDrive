import functools

class Pipe:
    def __init__(self, value):
        self._value = value

    @property
    def value(self):
        """パイプライン処理された最終的な値を取得します。"""
        return self._value


    # F# の |> (前方パイプライン) の模倣
    # 使用法: pipe_obj | function
    def __or__(self, func_or_funcs):
        if callable(func_or_funcs):
            return Pipe(func_or_funcs(self._value))
        elif isinstance(func_or_funcs, (list, tuple)): # 関数のリスト/タプルを順次適用
            current_val = self._value
            for f_in_seq in func_or_funcs:
                if not callable(f_in_seq):
                    raise TypeError(
                        f"パイプライン内のオブジェクト {f_in_seq} は呼び出し可能ではありません。"
                    )
                current_val = f_in_seq(current_val)
            return Pipe(current_val)
        else:
            # NotImplementedを返すと、Pythonは func_or_funcs.__ror__(self) を試みる可能性がある
            # (ただし、このケースでは通常TypeErrorが適切)
            raise TypeError(
                f"パイプライン演算子 '|' の右辺は呼び出し可能なオブジェクトまたはそのリスト/タプルである必要があります。"
            )

    def __repr__(self):
        return f"Pipe({self._value!r})"

class BackwardPipeableFunction:
    def __init__(self, func):
        self.func_to_apply = func

    # F# の <| (後方パイプライン) の模倣
    # 使用法: backward_pipeable_func < value_or_pipe_obj
    def __lt__(self, other_operand):
        # other_operand は Pipe インスタンスか、または素の値
        value_to_process = other_operand.value if isinstance(other_operand, Pipe) else other_operand
        return Pipe(self.func_to_apply(value_to_process)) # 結果は常にPipeインスタンス

    # ラップされた関数を直接呼び出せるようにする (オプション)
    def __call__(self, *args, **kwargs):
        return self.func_to_apply(*args, **kwargs)

if __name__ == '__main__':
    # パイプラインを開始するためのヘルパー (Pipeの省略形)
    P = Pipe

    # 後方パイプライン用の関数をラップするヘルパー
    B = BackwardPipeableFunction

    # --- 使用例 ---

    # テスト用の関数
    def add(x, y):
        # print(f"add({x}, {y}) called") # デバッグ用
        return x + y

    def multiply(x, y):
        # print(f"multiply({x}, {y}) called") # デバッグ用
        return x * y

    def subtract(x, y):
        # print(f"subtract({x}, {y}) called") # デバッグ用
        return x - y

    def square(x):
        # print(f"square({x}) called") # デバッグ用
        return x * x

    print("--- 前方パイプライン (|) のテスト ---")
    initial_value_a = 10

    resultA_obj = (P(initial_value_a)
                   | square
                   | (lambda x: add(x, 5))
                   | (lambda x: multiply(x, 2)))

    resultA = resultA_obj.value
    print(f"resultA: {resultA}") # 期待値: 210

    print("\n--- 後方パイプライン (<) のテスト (修正版) ---")
    initial_value_b = 3

    # 各関数を B() でラップします
    # F#: let resultB = multiply 4 <| add 10 <| square <| initial_value_b
    # Python (括弧とラッパーが必要):
    # B(multiply_func) < (B(add_func) < (B(square_func) < initial_value_b_or_P_obj))

    resultB_obj = ( B(lambda x: multiply(4, x))
                  < (B(lambda x: add(10, x))
                     < (B(square)
                        # 右端は Pipe オブジェクトでも素の値でも可
                        < initial_value_b ))) # P(initial_value_b) でも可

    resultB = resultB_obj.value
    print(f"resultB: {resultB}") # 期待値: 76


    print("\n--- 複数の引数をとる関数の例 (functools.partialまたはlambdaを使用) ---")
    def process_fs_style(a, b, piped_value):
        # print(f"process_fs_style({a}, {b}, {piped_value}) called") # デバッグ用
        return a + b * piped_value

    # 前方パイプライン
    result_fs_style_forward = (P(10)
                               | (lambda p_val: process_fs_style(5, 2, p_val))
                              ).value
    print(f"前方パイプライン (lambda): {result_fs_style_forward}") # 期待値: 25

    # 後方パイプライン
    result_fs_style_backward = ( B(lambda p_val: process_fs_style(5, 2, p_val))
                               < P(10) # または < 10
                               ).value
    print(f"後方パイプライン (lambda): {result_fs_style_backward}") # 期待値: 25

    # functools.partial を使う場合 (前方)
    # partial は callable なのでそのまま渡せる
    add_five_to_piped = functools.partial(add, 5) # y=5 が固定され、add(x, 5) となる関数

    result_partial_forward = (P(20)
                              | add_five_to_piped # add(20, 5)
                             ).value
    print(f"前方パイプライン (partial): {result_partial_forward}") # 期待値: 25

    # functools.partial を使う場合 (後方)
    # B() でラップする必要がある
    result_partial_backward = ( B(add_five_to_piped)
                               < P(30) # add(30, 5)
                              ).value
    print(f"後方パイプライン (partial): {result_partial_backward}") # 期待値: 35