package com.opethic.hrms.HRMSNew.repositories.master;


import com.opethic.hrms.HRMSNew.models.master.TransactionStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface TransactionStatusRepository extends JpaRepository<TransactionStatus,Long> {
    List<TransactionStatus> findAllByStatus(boolean b);

    TransactionStatus findByStatusNameAndStatus(String opened,boolean status);
}
