package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.AssociateGroups;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface AssociateGroupsRepository extends JpaRepository<AssociateGroups, Long> {
    AssociateGroups findByIdAndStatus(long associates_id, boolean b);

    @Query(
            value = " SELECT associates_name FROM `associates_groups_tbl` WHERE id=?1 AND Status=?2",
            nativeQuery = true
    )
    String findName(Long associateId, boolean b);

    List<AssociateGroups> findByCompanyId(Long id);


    @Query(
            value = " SELECT * FROM associates_groups_tbl WHERE company_id=?1 AND (branch_id=?2 OR branch_id IS NULL) " +
                    "AND principle_id=?3 AND (principle_groups_id=?4 OR principle_groups_id IS NULL) " +
                    "AND associates_name=?5 AND status=?6", nativeQuery = true
    )
    AssociateGroups findDuplicateAG(Long outletId, Long branchId, Long principleId, Long pgroupId,
                                    String associates_name, Boolean status);

    List<AssociateGroups> findByCompanyIdAndStatusAndBranchIdOrderByIdDesc(Long id, boolean b, Long id1);

    List<AssociateGroups> findByCompanyIdAndStatusAndBranchIsNullOrderByIdDesc(Long id, boolean b);
    List<AssociateGroups> findByCompanyIdAndStatus(Long id, boolean b);

    List<AssociateGroups> findByStatus(boolean b);
//    List<AssociateGroups> findByCompanyIdAndStatusAndBranchIdOrderByIdDesc(Long id, boolean b, Long id1);
//
//    List<AssociateGroups> findByCompanyIdAndStatusAndBranchIsNullOrderByIdDesc(Long id, boolean b);
}
