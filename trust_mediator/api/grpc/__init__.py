"""gRPC mediation API (FR-IG-02). Optional — requires the [grpc] extra.

Regenerate stubs after editing protos/mediation.proto:

    python -m grpc_tools.protoc -I trust_mediator/api/grpc/protos \
        --python_out=trust_mediator/api/grpc \
        --grpc_python_out=trust_mediator/api/grpc \
        trust_mediator/api/grpc/protos/mediation.proto

then re-point the import in mediation_pb2_grpc.py at
`trust_mediator.api.grpc` (protoc emits a bare `import mediation_pb2`).
"""
