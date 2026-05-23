# Heimdall (헤임달)

Heimdall은 **코드의 의도(문맥)와 논리(구조)**를 동시에 분석해 취약점 위험도를 산출하는 하이브리드 분석기입니다.

- **Semantic Engine**: Hugging Face `CodeBERT` 임베딩으로 코드-위험 시나리오 유사도를 측정
- **Structural Engine**: Python `ast` 기반으로 위험 호출/간단한 데이터 흐름(taint) 힌트를 탐지
- **Heimdall Core**: 두 엔진 결과를 결합해 최종 **위험 지수(risk index)** 산출

## 빠른 시작

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python .\scripts\analyze.py --file .\examples\sample.py
```

## 철학

> "단순한 패턴 매칭을 넘어, 코드의 의도와 논리를 동시에 꿰뚫어 본다."

## GitHub 공개 전 (민감 정보 점검)

```powershell
.\.venv\Scripts\python .\scripts\scan_secrets.py
```

- 실제 비밀값은 `.env`에만 두고, 템플릿은 `.env.example`을 참고하세요.
- 외부 취약점 연습 앱(PyGoat 등)을 같이 두었다면 스캔/커밋에서 제외: `--exclude pygoat`
- 자세한 내용: [SECURITY.md](SECURITY.md)

