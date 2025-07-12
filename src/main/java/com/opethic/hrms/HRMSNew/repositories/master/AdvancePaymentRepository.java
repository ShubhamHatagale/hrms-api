package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.AdvancePayment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.LocalDate;
import java.util.List;

public interface AdvancePaymentRepository extends JpaRepository<AdvancePayment, Long> {
    List<AdvancePayment> findByStatus(boolean b);

    List<AdvancePayment> findByEmployeeIdAndStatus(Long id, boolean b);

    AdvancePayment findByIdAndStatus(Long paymentId, boolean b);

    List<AdvancePayment> findByEmployeeIdAndStatusOrderByIdDesc(Long id, boolean b);

    @Query(value = "SELECT IFNULL(SUM(paid_amount),0) FROM `advance_payment_tbl` WHERE employee_id='?1' AND YEAR" +
            "(date_of_request)='?2' AND MONTH(date_of_request)='?3' AND payment_status='APPROVED' AND status=1", nativeQuery = true)
    double getEmployeeAdvanceOfMonth(Long employeeId, int year, int monthValue);

    @Query(value = "SELECT * FROM advance_payment_tbl WHERE date_of_request between ?1 AND ?2 AND status=1", nativeQuery = true)
    List<AdvancePayment> getPaymentRequestsBetweenDates(String fromDate, String toDate);

    @Query(value = "SELECT * FROM advance_payment_tbl WHERE MONTH(date_of_request) = ?1 AND YEAR(date_of_request) = ?2 AND status=1", nativeQuery = true)
    List<AdvancePayment> getPaymentRequestsForCurrentMonth(int month, int year);
    @Query(value = "SELECT * FROM advance_payment_tbl WHERE date_of_request between '?1' AND '?2' AND is_installment=1 AND payment_status=1 AND status=1", nativeQuery = true)
    List<AdvancePayment> getPaymentRequestsWithInstallmentsBetweenDates(String fromDate, String toDate);

    @Query(value = "SELECT * FROM advance_payment_tbl WHERE MONTH(date_of_request) = ?1 AND YEAR(date_of_request) = ?2  AND paid_amount <= request_amount" +
            " AND is_installment=1 AND payment_status=1 AND status=1", nativeQuery = true)
    List<AdvancePayment> getPaymentRequestsWithInstallmentsForCurrentMonth(String month, String year);
}
