package demo;

import javax.persistence.EntityManager;
import java.util.List;

public class ReportDao {
    private EntityManager em;

    public List<?> recent() {
        // one constant query, split over lines for readability
        return em.createNativeQuery(
            "SELECT id, title " +
            "FROM report " +
            "WHERE created_at > now() - interval '7 days'"
        ).getResultList();
    }
}
