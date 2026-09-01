### graph_to_terraform

AWSHound OpenGraph `graph.json` 또는 `graph.zip`을 분석해 공격 경로별 Terraform 소스 파일을 생성하는 Generation-only 도구입니다.

```text
OpenGraph JSON/ZIP
→ Node·Edge 분석
→ 공격 경로·Layer 분류
→ Terraform Resource·IAM 관계 생성
```

이 도구는 AWS API에 연결하거나 Terraform을 실행하지 않습니다.

#### 실행 환경

- Python 3.10 이상
- 외부 Python 패키지 불필요
- AWS 자격증명 불필요
- Terraform·Docker 불필요

#### 사용법

```powershell
py ".\awshound_pipeline\graph2terraform.py" `
  --input "C:\path\graph.zip" `
  --output ".\generated-terraform"
```

특정 시나리오만 생성:

```powershell
py ".\awshound_pipeline\graph2terraform.py" `
  --input "C:\path\graph.zip" `
  --output ".\generated-terraform" `
  --scenario lambda-004
```

#### 생성 결과

```text
generated-terraform/
├─ conversion-summary.json
└─ <scenario-id>/
   ├─ main.tf
   ├─ variables.tf
   ├─ outputs.tf
   ├─ terraform.tfvars.example
   ├─ required-inputs.json
   ├─ terraform-coverage.json
   ├─ conversion-manifest.json
   └─ fixtures/
```

#### 안전 범위

다음 작업은 수행하지 않습니다.

- AWS API 호출
- Terraform `init`, `plan`, `apply`
- AWS Resource 생성·변경
- 공격 실행
- 실제 Secret·고객 데이터 복사

Terraform State, 실제 `terraform.tfvars`, Artifact와 생성 출력은 `.gitignore`로 제외합니다.

#### 지원 범위

- AWSHound 공식 `AWS_*` Node·Edge
- 알려진 공격 패턴과 Generic IAM·Workload·Data Renderer
- 원본 Account ID·ARN의 Terraform 참조 치환
- 합성 S3·SSM Canary
- 미해결 Context·Artifact에 대한 Coverage Gate

현재 `RNR_*` Custom OpenGraph Node를 ALB·App·WAF Terraform으로 변환하는 Adapter는 포함하지 않습니다.

#### 테스트

```powershell
py -m unittest discover -s .\awshound_pipeline\tests -v
```

현재 자동 테스트 13개가 포함되어 있습니다.

#### 문서

- `awshound_pipeline/GRAPH2TERRAFORM.md`: 변환기 사용법
- `docs/mirror-implementation-standard-v1.md`: Layer별 Mirror 선정 표준
- `awshound_pipeline/schemas/AWSHOUND-LICENSE.txt`: 포함된 AWSHound Schema의 원본 라이선스
