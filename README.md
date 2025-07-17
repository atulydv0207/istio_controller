# istio_controller

                   ┌───────────────────────────────────────────────┐
                   │            External Clients / Users           │
                   └───────────────────────────────────────────────┘
                                     │
                                     ▼
                        ┌────────────────────────────┐
                        │     Kubernetes Gateway      │◄────── Kubernetes Gateway API (Istio implementation)
                        │ (Istio Gateway + Envoy)     │
                        └────────────────────────────┘
                                     │
                       ┌─────────────┴─────────────┐
                       ▼                           ▼
        ┌──────────────────────┐       ┌──────────────────────────┐
        │ External Auth Server │       │   Envoy Rate Limit Svc   │
        │    (e.g., apieky)    │       │ (Redis-backed via gRPC)  │
        └──────────────────────┘       └──────────────────────────┘
                 ▲                                ▲
         ┌───────┘                                │
         │       API key checked via              │
         │       Envoy External Auth              │
         │                                        │
         ▼                                        │
 ┌─────────────────────┐                   ┌──────────────┐
 │     UsagePlan CRD    │─────────────────►│ Redis Store  │
 │ (Contains auth, rate │                   └──────────────┘
 │  limit, quota config)│
 └─────────────────────┘
             │
             ▼
   ┌────────────────────┐
   │ Kubernetes Services│
   └────────────────────┘
