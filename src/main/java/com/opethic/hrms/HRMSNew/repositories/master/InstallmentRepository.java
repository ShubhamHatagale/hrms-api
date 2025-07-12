package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Installment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface InstallmentRepository extends JpaRepository<Installment, Long> {
    List<Installment> findByAdvancePaymentId(Long id);

    @Query(value = "SELECT SUM(amount) FROM hrms_new_db.installment_tbl where advance_payment_id=?1", nativeQuery = true)
    Double getSumOfPaidAmount(Long id);
}
