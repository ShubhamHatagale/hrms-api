package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Branch;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface BranchRepository extends JpaRepository<Branch,Long> {

    Branch findByIdAndStatus(long id, boolean b);

    List<Branch> findByCompanyIdAndStatus(Long companyId, boolean b);

    List<Branch> findByStatus(boolean b);
}
