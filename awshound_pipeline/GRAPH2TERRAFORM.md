### graph2terraform

AWSHound OpenGraph `graph.json` 또는 ZIP을 Terraform 소스 파일로만 변환하는 단독 CLI다.

기본 Offline 모드는 AWS API에 연결하지 않는다. `--source-profile`을 지정하면 관련
Node의 등록된 읽기 전용 Context API만 호출한다.

다음 작업은 어느 모드에서도 수행하지 않는다.

- AWS Resource 생성·변경 API
- Terraform 실행
- AWS Resource 배포
- 공격 실행
- 증적 수집
- Resource 삭제

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

#### AWS CLI Profile 연결

IAM Identity Center(SSO) 권장:

```powershell
aws configure sso --profile awshound-readonly
aws sso login --profile awshound-readonly
aws sts get-caller-identity --profile awshound-readonly
```

승인된 실습용 Access Key Profile:

```powershell
aws configure --profile awshound-readonly
```

Profile 이름을 변환기에 전달:

```powershell
py ".\awshound_pipeline\graph2terraform.py" `
  --input "C:\path\graph.zip" `
  --output ".\generated-terraform" `
  --source-profile awshound-readonly
```

Access Key는 AWS CLI Profile에만 저장하고 JSON·Terraform·Repository에는 넣지 않는다.
Profile Account ID는 Graph Source Account ID와 일치해야 한다.

#### 생성 파일

```text
generated-terraform/
├─ conversion-summary.json
└─ <scenario-id>/
   ├─ main.tf
   ├─ variables.tf
   ├─ outputs.tf
   ├─ terraform.tfvars.example
   ├─ required-inputs.json
   ├─ terraform-coverage.json     # Generic 경로일 때
   ├─ context-evidence.json       # --source-profile 사용 시
   ├─ conversion-manifest.json
   └─ fixtures/                   # 합성 코드가 필요할 때
```

#### 입력 범위

- AWSHound 공식 `AWS_*` Node·Edge는 고정밀 또는 Generic Renderer로 처리한다.
- 그래프에 없는 코드·AMI·Secret·Network 세부 설정은 생성하지 않고 `required-inputs.json` 또는 `terraform-coverage.json`에 기록한다.
- `RNR_*` Custom Node의 실제 Terraform 생성은 통합 Graph의 Property Contract와 RNR Renderer가 추가되어야 한다.

#### 안전 원칙

- 원본 AWS Access Key·Secret을 Terraform에 기록하지 않는다.
- 실제 S3·SSM·Secret 값은 복사하지 않는다.
- 원본 Account ID·ARN은 대상 Resource 참조로 사용하지 않고 새 Terraform 참조로 치환한다.
- 미해결 필수 항목이 있으면 Coverage Gate를 생성한다.

#### 포함된 AWSHound Schema Registry

Generic Edge 분류에 필요한 AWSHound Schema와 Traversable Edge Metadata는
`awshound_pipeline/schemas/`에 고정 커밋 기준으로 포함되어 있다. 원본 라이선스는
`AWSHOUND-LICENSE.txt`를 따른다.
