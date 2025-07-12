package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Designation;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface DesignationRepository extends JpaRepository<Designation, Long> {
    Designation findByIdAndStatus(Long designationId, boolean b);

    List<Designation> findAllByCompanyIdAndStatus(Long companyId, boolean b);

    List<Designation> findAllByStatus(boolean b);

    List<Designation> findByCompanyIdAndBranchIdAndStatus(Long id, Long id1, boolean b);
}
