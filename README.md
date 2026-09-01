### graph_to_terraform

AWSHound OpenGraph `graph.json` 또는 `graph.zip`을 분석해 공격 경로별 Terraform 소스 파일을 생성하는 Generation-only 도구입니다.

```text
AWSHound 또는 RNR 통합 OpenGraph JSON/ZIP
→ Node·Edge 분석
→ 공격 경로·Layer 분류
→ Terraform Resource·IAM 관계 생성
```

기본 Offline 모드는 AWS API에 연결하지 않습니다. `--source-profile`을 명시한
경우에만 읽기 전용 Context API를 호출합니다. Terraform은 어느 모드에서도 실행하지
않습니다.

#### 실행 환경

- Python 3.10 이상
- 외부 Python 패키지 불필요
- Offline 변환 시 AWS 자격증명 불필요
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

#### 선택적 AWS Context 수집

그래프에 부족한 Resource 설정을 원본 AWS의 읽기 API로 보충하려면 AWS CLI
Profile을 지정합니다.

권장 방식인 IAM Identity Center(SSO):

```powershell
aws configure sso --profile awshound-readonly
aws sso login --profile awshound-readonly
aws sts get-caller-identity --profile awshound-readonly
```

승인된 Access Key를 사용해야 하는 실습 환경:

```powershell
aws configure --profile awshound-readonly
```

Access Key는 AWS CLI Prompt에만 입력하고 Repository·JSON·Terraform에 기록하지
않습니다.

```powershell
py ".\awshound_pipeline\graph2terraform.py" `
  --input "C:\path\graph.zip" `
  --output ".\generated-terraform" `
  --source-profile awshound-readonly
```

Profile Account ID가 Graph의 Source Account ID와 다르면 중단합니다. 수집 결과는
`context-evidence.json`에 저장됩니다.

Profile을 지정하지 않아도 `context-plan.json`에는 해당 경로에 필요한 읽기 API 목록이
생성됩니다. 실제 API 호출은 `--source-profile`을 지정했을 때만 수행됩니다.

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
   ├─ context-plan.json
   ├─ terraform-coverage.json
   ├─ conversion-manifest.json
   └─ fixtures/
```

#### 안전 범위

다음 작업은 수행하지 않습니다.

- AWS Resource 생성·변경 API 호출
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

#### RNR 통합 경로 입력

팀의 통합 그래프처럼 `AWS_*`와 `RNR_*`가 함께 있어도 처리합니다.

- `RNR_CanReach`·`RNR_ForwardsTo`·`RNR_HasFinding`·`RNR_CanCompromiseWorkloadRole`을 연결해 하나의 통합 경로로 인식
- `RNR_AttachedSecurityGroup`·`RNR_ProtectedBy`·`RNR_ProtectedByNetworkAcl`·`RNR_LocatedIn`은 경로의 지원 설정으로 포함
- ALB ARN, WAF ARN, Security Group ID, Subnet ID, NACL ID가 있으면 `--source-profile`로 필요한 읽기 API만 계획·호출
- Code Finding과 Network Finding은 Terraform Resource가 아니라 경로 증적으로 보존

BloodHound 쿼리 결과를 넘길 때에도 최상위 구조는 다음과 같아야 합니다.

```json
{
  "graph": {
    "nodes": [],
    "edges": []
  }
}
```

특정 경로에 포함되는 모든 Node와 Edge를 함께 내보내야 하며, Edge의 `start.value`와
`end.value`는 `nodes[].id`를 가리켜야 합니다.

현재 팀 샘플의 `RNR_AppEndpoint`에는 경로·포트·서비스 이름만 있고 실제 ECS Service,
Task Definition, 컨테이너 이미지가 연결되어 있지 않습니다. 따라서 앱까지 실행 가능한
Terraform을 만들려면 각 AppEndpoint에 다음 정보가 추가되어야 합니다.

- `workload_id` 또는 `workload_arn`: 실제 EC2/ECS/Lambda 연결 식별자
- `artifact_uri` 또는 `image_digest`: 승인된 코드 패키지·AMI·컨테이너 이미지

해당 정보가 없으면 도구는 추측하지 않고 `terraform-coverage.json`과
`required-inputs.json`에 `APP_WORKLOAD_BINDING_REQUIRED`를 남겨 Apply를 차단합니다.

#### 테스트

```powershell
py -m unittest discover -s .\awshound_pipeline\tests -v
```

현재 자동 테스트 8개가 포함되어 있습니다.

#### 문서

- `awshound_pipeline/GRAPH2TERRAFORM.md`: 변환기 사용법
- `awshound_pipeline/schemas/AWSHOUND-LICENSE.txt`: 포함된 AWSHound Schema의 원본 라이선스
