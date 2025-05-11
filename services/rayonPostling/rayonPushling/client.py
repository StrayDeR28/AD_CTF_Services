import grpc
import mail_panda_pb2
import mail_panda_pb2_grpc

def get_messages(token_hex, server_address="localhost:50051"):
    # Подключаемся к серверу
    with grpc.insecure_channel(server_address) as channel:
        stub = mail_panda_pb2_grpc.MailPandaServiceStub(channel)
        # Формируем запрос
        request = mail_panda_pb2.TokenRequest(token_hex=token_hex)
        # Получаем поток сообщений
        try:
            for message in stub.GetMessagesByToken(request):
                print(f"{message.content}")
        except grpc.RpcError as e:
            print(f"Ошибка: {e.details()}")

if __name__ == '__main__':
    server_address = input("Введите адрес сервера (например, localhost:50051): ")
    token = input("Введите токен (HEX): ")
    get_messages(token, server_address)