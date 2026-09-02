from app.evaluation.schemas import EvaluationResult


def calculate_costs(results: list[EvaluationResult], input_price: float | None, output_price: float | None) -> dict:
    count = len(results)
    input_tokens = sum(item.usage.input_tokens for item in results)
    output_tokens = sum(item.usage.output_tokens for item in results)
    total_tokens = sum(item.usage.total_tokens for item in results)
    payload = {
        "average_input_tokens_per_rule": input_tokens / count if count else 0.0,
        "average_output_tokens_per_rule": output_tokens / count if count else 0.0,
        "average_total_tokens_per_rule": total_tokens / count if count else 0.0,
        "total_input_tokens": input_tokens,
        "total_output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }
    if input_price is None or output_price is None:
        payload["cost_status"] = "COST_NOT_CALCULATED"
        payload["estimated_total_cost"] = None
        payload["estimated_cost_per_rule"] = None
    else:
        total_cost = input_tokens / 1_000_000 * input_price + output_tokens / 1_000_000 * output_price
        payload["cost_status"] = "CALCULATED_FROM_CONFIG"
        payload["estimated_total_cost"] = total_cost
        payload["estimated_cost_per_rule"] = total_cost / count if count else 0.0
    return payload

