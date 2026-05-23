import os

def validator(d):
    # [1] 별칭(Aliasing) 테스트: 레퍼런스를 복사해도 독이 따라가는가?
    target = d['p']
    
    # [2] 재할당(Re-assignment) 테스트: 변수를 안전한 값으로 덮어쓰면 독이 사라지는가?
    d['p'] = "fixed_command" 
    
    # [3] 교차 오염 테스트: 다른 변수에 옮겨진 독은 여전히 유효한가?
    os.system(f"echo 'Ref check: {target}'")  # 이건 탐지되어야 함 (target은 여전히 독임)
    os.system(f"echo 'Dict check: {d['p']}'") # 이건 안전해야 함 (방금 덮어씀)

def brain_melter():
    user_input = input("Deep injection: ")
    
    # [4] 복합 구조 및 흐름 테스트
    container = {"p": user_input, "s": "safe_val"}
    
    # [5] 죽은 코드 안의 가짜 범인 (속임수)
    if (10 * 2) < 15: # False
        os.system(user_input) # 무시되어야 함
        
    # [6] 함수 호출을 통한 정밀 분석 실행
    validator(container)

if __name__ == "__main__":
    brain_melter()