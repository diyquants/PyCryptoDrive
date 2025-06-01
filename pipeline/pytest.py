from pipeline import Pipe

# パイプラインを開始するためのヘルパー (Pipeの省略形)
P = Pipe

resA = (P(range(10))
               | (lambda x:[y^2 for y in x])
               | (lambda x:[y+1 for y in x])
               | sum).value

resB=P(range(100))|(lambda y:filter(lambda x:x%2==0,y))|(lambda y:map(lambda x:x^2,y))|list|print