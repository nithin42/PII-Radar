"""
Universal Evaluation Schema Contract Compliance Tests.

Ensures AgentGuard output satisfies standard LLM/Agent evaluation contracts:
- Future AGI {"result": bool, "reason": str}
- LangChain / CrewAI {"passed": bool, "violations": list}
- DeepEval / Ragas {"score": float}
"""

from __future__ import annotations

from pii_radar import AgentGuard


class TestEvaluationContractCompliance:
    """Verifies schema conformance for framework-agnostic integrations."""

    def test_clean_evaluation_contract(self) -> None:
        guard = AgentGuard()
        eval_dict = guard("Hello, how can I help you today?").to_dict()

        # Contract assertions
        assert isinstance(eval_dict, dict)
        assert "result" in eval_dict
        assert "passed" in eval_dict
        assert "score" in eval_dict
        assert "reason" in eval_dict
        assert "violations" in eval_dict

        # Type assertions
        assert eval_dict["result"] is True
        assert eval_dict["passed"] is True
        assert eval_dict["score"] == 1.0
        assert isinstance(eval_dict["reason"], str)
        assert eval_dict["violations"] == []

    def test_violation_evaluation_contract(self) -> None:
        guard = AgentGuard()
        key = "AK" + "IA1111222233334444"
        text = f"Confidential: {key}"
        eval_dict = guard(text).to_dict()

        assert eval_dict["result"] is False
        assert eval_dict["passed"] is False
        assert eval_dict["score"] == 0.0
        assert isinstance(eval_dict["reason"], str)
        assert len(eval_dict["violations"]) == 1

        v = eval_dict["violations"][0]
        assert v["category"] == "SECRET"
        assert v["type"] == "AWS_ACCESS_KEY"
        assert v["value"] == key
        assert v["confidence"] >= 0.95

    def test_futureagi_exact_signature_compatibility(self) -> None:
        """
        Verify that a 1-line Future AGI evaluator wrapper returns exactly
        what Future AGI's FunctionEvaluator engine expects.
        """
        guard = AgentGuard()

        def futureagi_eval_wrapper(text: str) -> dict:
            return guard.evaluate(text).to_dict()

        clean_out = futureagi_eval_wrapper("All systems operational.")
        assert clean_out["result"] is True
        assert "Clean" in clean_out["reason"]

        leak_out = futureagi_eval_wrapper(
            "Contact support@acme.org with ssn 123-45-6789"
        )
        assert leak_out["result"] is False
        assert "Security violation" in leak_out["reason"]
