import os
import subprocess

# [시나리오 1: 세척기(Sanitizer) - 과탐 테스트]
def safe_execute(user_data):
    # 독을 깨끗하게 씻어내는 로직일세. (실제로는 안전함)
    clean_data = user_data.replace(";", "").replace("&", "").replace("|", "")
    os.system(f"echo {clean_data}")

# [시나리오 2: 딕셔너리 은닉(Field-sensitivity) - 미탐 테스트]
def dictionary_trap():
    data = {"safe": "echo Hello", "poison": input()}
    # 독은 'poison'에 들었는데, 정작 실행은 'safe'를 하네.
    # 헤임달이 'data'라는 바구니 전체를 독으로 볼지, 칸막이를 구분할지 보세나.
    os.system(data["safe"])

# [시나리오 3: 도달 불가능한 경로(Dead Code) - 논리 테스트]
def unreachable_threat():
    user_input = input()
    if False:  # 절대로 실행될 수 없는 조건문일세.
        os.system(user_input)

if __name__ == "__main__":
    raw = input("데이터 입력: ")
    safe_execute(raw)
    dictionary_trap()
    unreachable_threat()