"""External intelligence sensor boundary."""
from .policy import decision_weight,is_external_producer
def normalize_external_signal(producer:str,matched:bool,feed_off:bool)->dict:
    return {"producer":producer,"matched":bool(matched),"external":is_external_producer(producer),
            "decision_weight":decision_weight(feed_off,producer),"ground_truth":False}
