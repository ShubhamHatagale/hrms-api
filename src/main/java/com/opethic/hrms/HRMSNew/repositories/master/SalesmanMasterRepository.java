package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.SalesManMaster;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface SalesmanMasterRepository extends JpaRepository<SalesManMaster, Long> {
    SalesManMaster findByIdAndStatus(long id, boolean b);

    List<SalesManMaster> findByCompanyIdAndStatusAndBranchId(Long outletId, boolean b, Long id);

    List<SalesManMaster> findByCompanyIdAndStatusAndBranchIsNull(Long outletId, boolean b);
}
