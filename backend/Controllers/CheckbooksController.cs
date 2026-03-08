using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using CheckFillingAPI.Data;
using CheckFillingAPI.Models;
using CheckFillingAPI.Services;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace CheckFillingAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class CheckbooksController : ControllerBase
{
    private readonly AppDbContext _context;
    private readonly IAuditService _auditService;

    public CheckbooksController(AppDbContext context, IAuditService auditService)
    {
        _context = context;
        _auditService = auditService;
    }

    private int GetCurrentUserId()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return int.Parse(userIdClaim ?? "0");
    }

    // Helper method to get the creator of a checkbook via AuditLog
    private async Task<User?> GetCheckbookCreatorAsync(int checkbookId)
    {
        var auditLog = await _context.AuditLogs
            .Include(a => a.User)
            .Where(a => a.Action == "CREATE_CHECKBOOK" && a.EntityType == "Checkbook" && a.EntityId == checkbookId)
            .OrderBy(a => a.CreatedAt)
            .FirstOrDefaultAsync();

        return auditLog?.User;
    }

    // Helper method to check if current user has access to a checkbook
    private async Task<bool> HasAccessToCheckbookAsync(int checkbookId, User currentUser)
    {
        // Admin and direction have full access
        if (currentUser.Role == "admin" || currentUser.Role == "direction")
            return true;

        var creator = await GetCheckbookCreatorAsync(checkbookId);
        if (creator == null)
            return false; // If no creator found, deny access by default

        // Regionale users can only access checkbooks created by their region
        if (currentUser.Role == "regionale")
        {
            return creator.Role == "regionale" && 
                   creator.Region == currentUser.Region && 
                   !string.IsNullOrEmpty(currentUser.Region);
        }

        // Comptabilite users can only access checkbooks created by comptabilite
        if (currentUser.Role == "comptabilite")
        {
            return creator.Role == "comptabilite";
        }

        return false;
    }

    // GET: api/checkbooks
    [HttpGet]
    public async Task<ActionResult<IEnumerable<object>>> GetCheckbooks([FromQuery] int? bankId)
    {
        var userId = GetCurrentUserId();
        var currentUser = await _context.Users.FindAsync(userId);
        
        if (currentUser == null)
            return Unauthorized();

        var query = _context.Checkbooks.Include(c => c.Bank).AsQueryable();
        
        if (bankId.HasValue)
        {
            query = query.Where(c => c.BankId == bankId.Value);
        }

        var allCheckbooks = await query
            .OrderByDescending(c => c.CreatedAt)
            .ToListAsync();

        // Filter based on user role
        var filteredCheckbooks = new List<Checkbook>();
        
        if (currentUser.Role == "admin" || currentUser.Role == "direction")
        {
            // Admin and direction see everything
            filteredCheckbooks = allCheckbooks;
        }
        else
        {
            // Filter for regionale and comptabilite
            foreach (var checkbook in allCheckbooks)
            {
                if (await HasAccessToCheckbookAsync(checkbook.Id, currentUser))
                {
                    filteredCheckbooks.Add(checkbook);
                }
            }
        }

        var result = filteredCheckbooks.Select(c => new
        {
            c.Id,
            c.BankId,
            BankName = c.Bank.Name,
            c.AgencyName,
            c.AgencyCode,
            c.Serie,
            c.StartNumber,
            c.EndNumber,
            c.Capacity,
            c.UsedCount,
            Remaining = c.Capacity - c.UsedCount,
            c.CreatedAt
        }).ToList();

        return Ok(result);
    }

    // GET: api/checkbooks/5
    [HttpGet("{id}")]
    public async Task<ActionResult<object>> GetCheckbook(int id)
    {
        var userId = GetCurrentUserId();
        var currentUser = await _context.Users.FindAsync(userId);
        
        if (currentUser == null)
            return Unauthorized();

        var checkbook = await _context.Checkbooks
            .Include(c => c.Bank)
            .Where(c => c.Id == id)
            .FirstOrDefaultAsync();

        if (checkbook == null)
        {
            return NotFound(new { message = "Chéquier non trouvé" });
        }

        // Check access for regionale and comptabilite
        if (currentUser.Role == "regionale" || currentUser.Role == "comptabilite")
        {
            if (!await HasAccessToCheckbookAsync(id, currentUser))
            {
                return StatusCode(403, new { message = "Accès refusé à ce chéquier" });
            }
        }

        var result = new
        {
            checkbook.Id,
            checkbook.BankId,
            BankName = checkbook.Bank.Name,
            checkbook.AgencyName,
            checkbook.AgencyCode,
            checkbook.Serie,
            checkbook.StartNumber,
            checkbook.EndNumber,
            checkbook.Capacity,
            checkbook.UsedCount,
            Remaining = checkbook.Capacity - checkbook.UsedCount,
            checkbook.CreatedAt
        };

        return Ok(result);
    }

    // POST: api/checkbooks
    [HttpPost]
    public async Task<ActionResult<object>> CreateCheckbook([FromBody] CreateCheckbookRequest request)
    {
        // Validation
        if (request.Serie.Length != 2)
        {
            return BadRequest(new { message = "La série doit contenir exactement 2 caractères" });
        }

        if (request.StartNumber < 0 || request.StartNumber > 9999999)
        {
            return BadRequest(new { message = "Le numéro de début doit être entre 0 et 9999999" });
        }

        if (request.EndNumber < 0 || request.EndNumber > 9999999)
        {
            return BadRequest(new { message = "Le numéro de fin doit être entre 0 et 9999999" });
        }

        if (request.EndNumber < request.StartNumber)
        {
            return BadRequest(new { message = "Le numéro de fin doit être supérieur ou égal au numéro de début" });
        }

        var capacity = request.EndNumber - request.StartNumber + 1;

        // Vérifier que la banque existe
        var bank = await _context.Banks.FindAsync(request.BankId);
        if (bank == null)
        {
            return NotFound(new { message = "Banque non trouvée" });
        }

        // Vérifier unicité
        var exists = await _context.Checkbooks.AnyAsync(c =>
            c.BankId == request.BankId &&
            c.Serie == request.Serie &&
            c.StartNumber == request.StartNumber);

        if (exists)
        {
            return Conflict(new { message = "Ce chéquier existe déjà" });
        }

        var checkbook = new Checkbook
        {
            BankId = request.BankId,
            AgencyName = request.AgencyName,
            AgencyCode = request.AgencyCode,
            Serie = request.Serie.ToUpper(),
            StartNumber = request.StartNumber,
            EndNumber = request.EndNumber,
            Capacity = capacity,
            UsedCount = 0,
            CreatedAt = DateTime.UtcNow
        };

        _context.Checkbooks.Add(checkbook);
        await _context.SaveChangesAsync();

        var userId = GetCurrentUserId();
        await _auditService.LogAction(
            userId,
            "CREATE_CHECKBOOK",
            "Checkbook",
            checkbook.Id,
            new
            {
                bankId = request.BankId,
                agencyName = request.AgencyName,
                agencyCode = request.AgencyCode,
                serie = request.Serie.ToUpper(),
                startNumber = request.StartNumber,
                endNumber = request.EndNumber,
                capacity = capacity
            });

        return CreatedAtAction(nameof(GetCheckbook), new { id = checkbook.Id }, new
        {
            checkbook.Id,
            checkbook.BankId,
            BankName = bank.Name,
            checkbook.AgencyName,
            checkbook.AgencyCode,
            checkbook.Serie,
            checkbook.StartNumber,
            checkbook.EndNumber,
            checkbook.Capacity,
            checkbook.UsedCount,
            Remaining = checkbook.Capacity - checkbook.UsedCount,
            checkbook.CreatedAt
        });
    }

    // PUT: api/checkbooks/5
    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateCheckbook(int id, [FromBody] UpdateCheckbookRequest request)
    {
        var userId = GetCurrentUserId();
        var currentUser = await _context.Users.FindAsync(userId);
        
        if (currentUser == null)
            return Unauthorized();

        var checkbook = await _context.Checkbooks.FindAsync(id);
        if (checkbook == null)
        {
            return NotFound(new { message = "Chéquier non trouvé" });
        }

        // Check access for regionale and comptabilite
        if (currentUser.Role == "regionale" || currentUser.Role == "comptabilite")
        {
            if (!await HasAccessToCheckbookAsync(id, currentUser))
            {
                return StatusCode(403, new { message = "Accès refusé à ce chéquier" });
            }
        }

        // Vérifier que le chéquier n'a jamais été utilisé
        if (checkbook.UsedCount > 0)
        {
            return BadRequest(new { message = "Impossible de modifier un chéquier qui a été utilisé." });
        }

        var oldValues = new
        {
            agencyName = checkbook.AgencyName,
            agencyCode = checkbook.AgencyCode
        };

        checkbook.AgencyName = request.AgencyName;
        checkbook.AgencyCode = request.AgencyCode;

        await _context.SaveChangesAsync();

        var newValues = new
        {
            agencyName = request.AgencyName,
            agencyCode = request.AgencyCode
        };

        await _auditService.LogAction(
            userId,
            "UPDATE_CHECKBOOK",
            "Checkbook",
            checkbook.Id,
            new { oldValues, newValues });

        return NoContent();
    }

    // DELETE: api/checkbooks/5
    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteCheckbook(int id)
    {
        var userId = GetCurrentUserId();
        var currentUser = await _context.Users.FindAsync(userId);
        
        if (currentUser == null)
            return Unauthorized();

        var checkbook = await _context.Checkbooks.FindAsync(id);
        if (checkbook == null)
        {
            return NotFound(new { message = "Chéquier non trouvé" });
        }

        // Check access for regionale and comptabilite
        if (currentUser.Role == "regionale" || currentUser.Role == "comptabilite")
        {
            if (!await HasAccessToCheckbookAsync(id, currentUser))
            {
                return StatusCode(403, new { message = "Accès refusé à ce chéquier" });
            }
        }

        // Vérifier que le chéquier n'a jamais été utilisé
        if (checkbook.UsedCount > 0)
        {
            return BadRequest(new { message = "Impossible de supprimer un chéquier qui a été utilisé." });
        }

        // Vérifier s'il y a des chèques liés
        var hasChecks = await _context.Checks.AnyAsync(c => c.CheckbookId == id);
        if (hasChecks)
        {
            return BadRequest(new { message = "Impossible de supprimer un chéquier contenant des chèques" });
        }

        var deletedCheckbookData = new
        {
            bankId = checkbook.BankId,
            agencyName = checkbook.AgencyName,
            agencyCode = checkbook.AgencyCode,
            serie = checkbook.Serie,
            startNumber = checkbook.StartNumber,
            endNumber = checkbook.EndNumber,
            capacity = checkbook.Capacity
        };

        _context.Checkbooks.Remove(checkbook);
        await _context.SaveChangesAsync();

        await _auditService.LogAction(
            userId,
            "DELETE_CHECKBOOK",
            "Checkbook",
            id,
            deletedCheckbookData);

        return NoContent();
    }

    // GET: api/checkbooks/{id}/next-reference
    [HttpGet("{id}/next-reference")]
    public async Task<ActionResult<object>> GetNextReference(int id)
    {
        var userId = GetCurrentUserId();
        var currentUser = await _context.Users.FindAsync(userId);
        
        if (currentUser == null)
            return Unauthorized();

        var checkbook = await _context.Checkbooks.FindAsync(id);
        if (checkbook == null)
        {
            return NotFound(new { message = "Chéquier non trouvé" });
        }

        // Check access for regionale and comptabilite
        if (currentUser.Role == "regionale" || currentUser.Role == "comptabilite")
        {
            if (!await HasAccessToCheckbookAsync(id, currentUser))
            {
                return StatusCode(403, new { message = "Accès refusé à ce chéquier" });
            }
        }

        if (checkbook.UsedCount >= checkbook.Capacity)
        {
            return BadRequest(new { message = "Chéquier complet" });
        }

        // Récupérer tous les chèques de ce chéquier
        var usedChecks = await _context.Checks
            .Where(c => c.CheckbookId == id)
            .Select(c => c.Reference)
            .ToListAsync();

        // Parser les numéros utilisés (format: SérieNUMÉRO ex: AA0000001)
        var usedNumbers = new HashSet<int>();
        foreach (var checkRef in usedChecks)
        {
            if (!string.IsNullOrEmpty(checkRef) && checkRef.Length > 2)
            {
                var numStr = checkRef.Substring(checkbook.Serie.Length);
                if (int.TryParse(numStr, out var num))
                {
                    usedNumbers.Add(num);
                }
            }
        }

        // Trouver le premier numéro libre dans l'intervalle
        int nextNumber = checkbook.StartNumber;
        while (nextNumber <= checkbook.EndNumber && usedNumbers.Contains(nextNumber))
        {
            nextNumber++;
        }

        if (nextNumber > checkbook.EndNumber)
        {
            return BadRequest(new { message = "Aucun numéro disponible dans cet intervalle" });
        }

        var nextReference = $"{checkbook.Serie}{nextNumber:D7}";

        return Ok(new { reference = nextReference, checkNumber = nextNumber });
    }
}

public record CreateCheckbookRequest(
    int BankId,
    string AgencyName,
    string AgencyCode,
    string Serie,
    int StartNumber,
    int EndNumber
);

public record UpdateCheckbookRequest(
    string AgencyName,
    string AgencyCode
);
