### Attack Path Mirror 구현 표준 v1.0

#### 1. 목적

AWSHound 및 Network·App 보안 도구에서 추출한 공격 경로를 실제로 검증하기 위해, 공격 성공에 필요한 최소 환경만 격리된 AWS 계정에 재구성한다.

```text
전체 AWS 환경 복제 X
선택된 Attack Path의 실행 필수 부분만 Replica 구성 O
```

Mirror 생성 완료가 최종 목표가 아니다. 공격 전 접근 거부, 필수 공격 단계 실행, 최종 Canary 성공까지 확인해야 검증 완료로 판정한다.

#### 2. 적용 Layer

| Layer | 범위 |
|---|---|
| Layer 1 | IAM·권한·Trust·Control Plane |
| Layer 2 | Lambda·EC2·EKS·ECS 등 Workload·Runtime |
| Layer 3 | App 코드·취약점·S3·SSM·Secret 등 App·Data |
| Layer 4 | VPC·Subnet·SG·Route·NACL·ALB·WAF 등 Network |

#### 3. 공통 Mirror 선정 규칙

각 Node·설정에 다음 질문을 적용한다.

```text
이 항목을 제거하면 다음 공격 단계가 실행되지 않거나 최종 결과가 달라지는가?
```

- 달라짐: Mirror 포함
- 달라지지 않음: 제외
- 환경 설정에 따라 달라짐: 원본 API로 Context 확인
- 실제 데이터만 필요함: 합성 Canary로 대체
- 복제 불가능함: `NON_REPRODUCIBLE`로 기록하고 배포 차단

#### 4. 공격 행동 분류

| 분류 | 의미 | Mirror 처리 |
|---|---|---|
| 정찰·조회 | 대상 이름·설정 확인 | 원본 읽기 전용 Context로 사용, 공격 실행에서 생략 가능 |
| 권한 전환 | User·Role·Workload Role로 실행 주체 변경 | 관련 Policy·Trust를 Mirror하고 실제 전환 실행 |
| 설정·자원 변경 | Policy·Trust·코드·Resource 변경 | 변경 대상만 Partial Mirror |
| 실제 실행 | Lambda·EC2·App·Session 실행 | 필요한 Workload·App·Network만 Minimal Mirror |
| 최종 목표 달성 | 데이터 접근·관리자 권한 사용 | 합성 Canary로 성공 검증 |

예:

```text
ListRoles          → 정찰·조회
AssumeRole         → 권한 전환
UpdateFunctionCode → 설정·자원 변경
InvokeFunction     → 실제 실행
RunsAs             → 실행 권한 연결
GetObject          → 최종 목표 달성
```

#### 5. Mirror 수준

| 수준 | 선택 조건 | 처리 |
|---|---|---|
| M0: Mirror 생략 | 정적 분석·조회만으로 결론 가능 | 그래프·API·Policy Simulator 결과 저장 |
| M1: Canary 검증 | 영향이 작은 실제 요청만 필요 | 허가된 실습 계정에서 단기 요청 실행 |
| M2: Partial Mirror | IAM·Resource 변경 필요 | 변경되는 IAM·Resource만 구성 |
| M3: Minimal Cross-Layer Mirror | Runtime·App·Network가 공격 조건 | 필요한 Layer의 최소 부분을 하나의 Replica로 구성 |
| M4: Artifact Mirror | 기존 코드·OS·파일 상태가 공격 조건 | 승인된 ZIP·Image·AMI·Snapshot 사용 |

#### 6. Layer 1 — IAM 구현 규칙

##### 포함 기준

- 공격 시작 User·Role
- 공격에 필요한 최소 IAM Action
- 권한 전환 대상 Role
- Role Trust Policy
- 직접 연결된 Inline·Managed Policy
- 공격 결과에 영향을 주는 IAM Condition
- Permissions Boundary
- SCP·RCP
- Resource Policy

##### 제외 기준

- 공격과 관계없는 User·Role·Group
- 다른 서비스의 Policy
- Target이 이미 확인된 이후의 `List*`, `Get*` 정찰 실행
- 전체 계정 IAM 구조

##### 수집 근거

```text
AWSHound Graph
iam:GetUser
iam:GetRole
iam:GetPolicy
iam:GetPolicyVersion
iam:GetUserPolicy / GetRolePolicy
organizations:ListPoliciesForTarget
accessanalyzer:ValidatePolicy
iam:SimulatePrincipalPolicy
```

##### Terraform 구현

```text
AWS_User      → aws_iam_user
AWS_Role      → aws_iam_role
AWS_Policy    → aws_iam_policy
AWS_HasPolicy → policy_attachment
CanAssumeRole → Identity Policy + Trust Policy
```

원본 Account ID와 ARN은 대상 계정의 새 Resource 참조로 치환한다.

##### 검증 기준

```text
공격 전 최종 권한 사용 → AccessDenied
권한 전환·변경 실행
get-caller-identity → 예상 Role ARN 확인
```

#### 7. Layer 2 — Workload·Runtime 구현 규칙

##### 포함 기준

- 공격 대상 Lambda·EC2·EKS·ECS·CloudFormation
- Runtime·Handler·Architecture
- Execution Role·Instance Profile
- 공격 실행에 필요한 Trigger
- Lambda Code Signing
- EC2 Metadata Options
- Workload 상태와 Port
- 실행에 필요한 최소 코드·Image·AMI

##### 제외 기준

- 공격과 관계없는 Workload
- 운영용 Auto Scaling·백업·모니터링
- 공격에 사용하지 않는 Trigger
- 동일 공격에 필요하지 않은 다중 인스턴스

##### Artifact 선택

```text
공격자가 새 코드를 주입
→ 합성 공격 코드 사용

기존 코드 취약점 이용
→ 원본 Lambda ZIP·Layer·Container Image 사용

EC2 내부 OS·패키지·파일이 공격 조건
→ 승인된 AMI·EBS Snapshot 사용

새 EC2에 Role을 연결하는 공격
→ Snapshot 불필요
```

##### Terraform 구현

```text
Lambda → aws_lambda_function
EC2    → aws_instance
EKS    → aws_eks_cluster / node_group
ECS    → aws_ecs_task_definition / service
```

##### 검증 기준

```text
Workload 상태 Active·Running
Handler·App Process 정상
공격 코드 실행 성공
Execution Role ARN 확인
```

#### 8. Layer 3 — App·Data 구현 규칙

##### 포함 기준

- 공격에 사용되는 App Endpoint
- 취약점 Source·Sink
- 취약점 재현에 필요한 라이브러리·설정
- Semgrep Finding과 코드 Hash
- 최종 성공 확인용 S3·SSM·Secret·KMS Canary

##### 제외 기준

- 전체 Repository
- 공격과 관계없는 App Endpoint
- 운영 DB
- 실제 고객 데이터
- 실제 Secret·API Key
- 공격 성공과 무관한 App 기능

##### 데이터 처리

```text
원본 S3 Object    → 동일 Key의 합성 Object
원본 SSM Parameter → 테스트 Parameter
원본 Secret       → TEST_ONLY 값
원본 KMS Key       → 새 KMS Key와 합성 Ciphertext
```

KMS Key Material은 복제하지 않는다.

##### App 수집 우선순위

1. 고객 AWS 내부에서 Semgrep 실행 후 결과 JSON만 수집
2. 승인된 GitHub·GitLab·ZIP 검사
3. 승인된 EC2에서 SSM Run Command로 허용 범위만 검사
4. 원본 코드가 반드시 필요한 경우 승인된 Artifact 수집

##### 검증 기준

```text
취약 Endpoint 호출 성공
동적 Canary Callback 확인
상승한 Role로 합성 Data 접근
예상 Hash와 결과 Hash 일치
```

#### 9. Layer 4 — Network 구현 규칙

##### 포함 기준

- 공격 진입 Source·Destination
- ALB·Listener·Target Group
- 대상 Workload가 있는 Subnet
- 통신에 사용되는 Security Group Rule
- 실제 적용 Route Table
- 실제 차단·허용에 영향을 주는 NACL
- 필요한 IGW·NAT·VPC Endpoint
- 공격 요청에 영향을 주는 WAF Rule

##### 제외 기준

- 전체 VPC
- 다른 Subnet·SG·Route
- 공격과 관계없는 Peering·Transit Gateway
- 사용하지 않는 NAT·Endpoint
- 결과에 영향을 주지 않는 WAF·NACL

##### Network 의존성 확장

```text
Workload 조회
→ VPC·Subnet·SG 확인
→ Route·NACL 확인
→ Route Target에 따라 IGW·NAT·Endpoint 추가
→ 더 이상 필수 의존성이 없으면 확장 종료
```

##### Terraform 구현

```text
VPC       → aws_vpc
Subnet    → aws_subnet
SG        → aws_security_group / rule
Route     → aws_route_table / route
NACL      → aws_network_acl / rule
ALB       → aws_lb / listener / target_group
Endpoint  → aws_vpc_endpoint
```

##### 검증 기준

```text
설정 기반 Reachability 확인
ALB Target Health 정상
실제 HTTP·TCP Canary 성공
App Endpoint 응답 확인
```

#### 10. Layer 중첩 규칙

연쇄 공격에서는 모든 Layer를 무조건 Mirror하지 않는다. 각 필수 Edge가 요구하는 Layer의 합집합만 구성한다.

```text
각 Edge의 필수 Layer 표시
→ 합집합 계산
→ 실행 필수 의존성 추가
→ 중복 Resource 통합
→ 하나의 Path Replica 생성
```

예:

```text
User → AssumeRole → Lambda 변경·실행 → S3 접근

Layer 1: User·Role·Policy·Trust
Layer 2: Lambda·Runtime·Execution Role
Layer 3: 합성 S3 Object
Layer 4: 별도 Network 조건이 없으면 제외
```

다른 예:

```text
Internet → ALB → EC2 → SSRF → EC2 Role → S3

Layer 1: Instance Role·S3 Policy
Layer 2: ALB·EC2·Runtime
Layer 3: 취약 Endpoint·합성 S3 Object
Layer 4: VPC·Subnet·SG·Route·필요 Endpoint
```

#### 11. Cross-Layer 성공 판정

```text
공격자 신원 확인
→ 공격 전 최종 Target 접근 거부
→ 필수 Edge 순차 실행
→ Principal 전환 확인
→ 최종 Canary 성공
```

최종 판정:

```text
공격 전 AccessDenied
+ 모든 필수 Edge 실행 성공
+ 최종 Canary Hash 일치
= EXECUTION_VERIFIED
```

실패 상태:

```text
ATTACK_BLOCKED_AT_EDGE_n
MIRROR_ERROR
ENVIRONMENT_ERROR
CONTEXT_REQUIRED
```

#### 12. 필수 산출물

| 파일 | 목적 |
|---|---|
| `source-subgraph.json` | 선택된 원본 Node·Edge |
| `replica-scope.json` | 포함·조건부·제외 항목과 이유 |
| `context-evidence.json` | 원본 API 확인 결과 |
| `artifact-plan.json` | 코드·Image·Snapshot 처리 결정 |
| `replica-map.json` | 원본 Node·ARN과 Mirror Resource 매핑 |
| `terraform-coverage.json` | 복구 가능성·미해결 항목 |
| `validation-contract.json` | 공격 순서·Executor·성공 기준 |
| `execution-result.json` | 단계별 공격 실행 결과 |

#### 13. 배포 차단 기준

다음 항목이 미해결이면 Terraform Apply를 차단한다.

- 필수 IAM Trust·Policy 없음
- Workload Role 없음
- 필요한 App Artifact 없음
- EC2 AMI 결정 안 됨
- 필수 Network Route·SG 없음
- 성공 확인용 Canary 없음
- 복제 불가능한 외부 의존성 미처리

#### 14. 완료 정의

- [ ] 최소 공격 경로가 확정됨
- [ ] Layer별 포함·제외 이유가 기록됨
- [ ] 필요한 원본 Context가 수집됨
- [ ] 원본 ID가 Mirror ID로 치환됨
- [ ] Terraform Coverage Gate 통과
- [ ] Mirror Resource Readiness 통과
- [ ] 공격 전 Negative Precheck 통과
- [ ] 모든 필수 Edge 실행 성공
- [ ] 최종 Canary 성공
- [ ] 테스트 Resource Destroy 완료

#### 15. 최종 표준 문장

> Attack Path Mirror는 모든 Layer를 복제하지 않는다. 공격 경로의 각 필수 Edge를 실제로 실행하는 데 필요한 IAM, Workload, App·Data, Network 부분만 포함하고, 제거해도 공격 결과가 달라지지 않는 Resource는 제외한다. 원본 데이터는 합성 Canary로 대체하며, 기존 코드·AMI·WAF·NACL은 공격 성공 조건일 때만 포함한다.
