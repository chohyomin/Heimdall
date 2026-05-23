import os
import html

# [1] 데이터 전처리소: 한 번에 여러 데이터를 처리하여 반환
def preprocess(raw_input):
    safe_val = html.escape(raw_input)  # 세척됨
    risky_val = raw_input              # 오염됨
    return {"clean": safe_val, "dirty": risky_val}

# [2] 중간 유통망: 데이터를 받아서 다른 함수로 전달 (2단계 전파)
def middle_ware(data_packet):
    # 여기서 딕셔너리 내용물이 섞이지 않고 잘 유지되는지 확인
    final_execute(data_packet)

# [3] 최종 실행소: 폭탄(Sink)이 설치된 곳
def final_execute(packet):
    # (A) 안전한 데이터 사용 - 탐지되면 안 됨 (False Positive Check)
    os.system(f"echo 'Safe: {packet['clean']}'")
    
    # (B) 오염된 데이터 사용 - 반드시 탐지되어야 함 (True Positive Check)
    os.system(f"ls {packet['dirty']}")

# [4] 제어 로직: 논리적 장벽
def security_checkpoint():
    user_data = input("Enter command: ")
    
    # 정상 흐름 분석
    packet = preprocess(user_data)
    middle_ware(packet)
    
    # (C) 도달 불가능한 경로 - 탐지되면 안 됨 (Dead Code Check)
    if 2 + 2 == 5: # 명백한 거짓
        os.system(user_data)

if __name__ == "__main__":
    security_checkpoint()