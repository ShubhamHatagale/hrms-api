package com.opethic.hrms.HRMSNew.common;

import lombok.Data;

@Data
public class Enums {
    public enum InstallmentStatus {
        PENDING, PAID, OVERDUE
    }

    public enum PaymentStatus {
        PENDING, APPROVED, REJECTED
    }
}
