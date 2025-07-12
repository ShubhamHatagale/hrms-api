package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.TransactionTypeMaster;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TransactionTypeMasterRepository extends JpaRepository<TransactionTypeMaster, Long> {

    TransactionTypeMaster findByTransactionNameIgnoreCase(String tranxType);

    TransactionTypeMaster findByTransactionCodeIgnoreCase(String purchase_return);
}

