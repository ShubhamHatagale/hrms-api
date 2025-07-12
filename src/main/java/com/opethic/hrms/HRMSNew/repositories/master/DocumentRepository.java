package com.opethic.hrms.HRMSNew.repositories.master;

import com.opethic.hrms.HRMSNew.models.master.Document;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface DocumentRepository extends JpaRepository<Document, Long> {

    Document findByIdAndStatus(long documentId, boolean b);

    List<Document> findAllByCompanyIdAndStatus(Long companyId, boolean b);

    List<Document> findAllByStatus(boolean b);
    List<Document> findByCompanyIdAndBranchIdAndStatus(Long id, Long id1, boolean b);
}
