import os

def process_data(payload):
    # [1] 가짜 독: 세척기로 씻어낸 데이터 (안전해야 함)
    clean_val = payload.replace(";", "")
    
    # [2] 진짜 독: 씻지 않은 원본 데이터 (위험해야 함)
    raw_val = payload
    
    return {"safe": clean_val, "poison": raw_val}

def execute_service(data_dict):
    # [3] 필드 정밀 추적 테스트: 'safe' 키는 안전해야 함
    os.system(f"echo {data_dict['safe']}")
    
    # [4] 필드 정밀 추적 테스트: 'poison' 키는 위험을 잡아야 함
    os.system(f"ls {data_dict['poison']}")

def final_mission():
    user_input = input("공격 코드를 입력하세요: ")
    
    # [5] 함수 간 전파(Interprocedural) 테스트
    result = process_data(user_input)
    
    # [6] 실행 로직
    execute_service(result)
    
    # [7] 죽은 코드(Dead Code) 테스트: 이건 절대 안 나오나?
    if 1 == 0:
        os.system(user_input)

if __name__ == "__main__":
    final_mission()