package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.AreaMaster;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AreaMasterRepository extends JpaRepository<AreaMaster, Long> {
    List<AreaMaster> findByCompanyIdAndStatusAndBranchId(Long outletId, boolean b, Long id);

    List<AreaMaster> findByCompanyIdAndStatusAndBranchIsNull(Long outletId, boolean b);

    AreaMaster findByIdAndStatus(long id, boolean b);
}
