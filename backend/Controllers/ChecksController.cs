using CheckFillingAPI.Models;
using CheckFillingAPI.RealTime;
using CheckFillingAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using System.Security.Claims;
using CheckFillingAPI.Data;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace CheckFillingAPI.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class ChecksController : ControllerBase
{
    private readonly ICheckService _checkService;
    private readonly IAuditService _auditService;
    private readonly AppDbContext _context;
    private readonly IHubContext<CheckUpdatesHub> _hubContext;

    public ChecksController(
        ICheckService checkService,
        IAuditService auditService,
        AppDbContext context,
        IHubContext<CheckUpdatesHub> hubContext)
    {
        _checkService = checkService;
        _auditService = auditService;
        _context = context;
        _hubContext = hubContext;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
        var user = await _context.Users.FindAsync(userId);
        
        if (user == null)
            return Unauthorized();

        var checksQuery = _context.Checks
            .Include(c => c.Checkbook)
                .ThenInclude(cb => cb!.Bank)
            .AsQueryable();
        
        var checks = await checksQuery.ToListAsync();
        
        // Filter by region if user is regionale: show only checks from regionale users of the same region
        if (user.Role == "regionale" && !string.IsNullOrEmpty(user.Region))
        {
            var regionUserIds = await _context.Users
                .Where(u => u.Role == "regionale" && u.Region == user.Region)
                .Select(u => u.Id)
                .ToListAsync();
            checks = checks.Where(c => regionUserIds.Contains(c.UserId)).ToList();
        }

        var result = checks.Select(c => new
        {
            reference = c.Reference,
            userId = c.UserId,
            amount = c.Amount,
            payee = c.Payee,
            city = c.City,
            date = c.Date,
            bank = c.Checkbook?.Bank?.Name ?? "",
            ville = c.Ville,
            status = c.Status,
            motif = c.Motif,
            createdAt = c.CreatedAt
        });
        return Ok(result);
    }

    [HttpGet("user")]
    public async Task<IActionResult> GetByUser()
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
        var user = await _context.Users.FindAsync(userId);
        
        if (user == null)
            return Unauthorized();

        var checksQuery = _context.Checks
            .Where(c => c.UserId == userId)
            .Include(c => c.Checkbook)
                .ThenInclude(cb => cb!.Bank)
            .AsQueryable();
        
        var checks = await checksQuery.ToListAsync();

        var result = checks.Select(c => new
        {
            reference = c.Reference,
            userId = c.UserId,
            checkbookId = c.CheckbookId,
            amount = c.Amount,
            payee = c.Payee,
            city = c.City,
            date = c.Date,
            bank = c.Checkbook?.Bank?.Name ?? "",
            ville = c.Ville,
            status = c.Status,
            motif = c.Motif,
            createdAt = c.CreatedAt
        });
        return Ok(result);
    }

    [HttpGet("{reference}")]
    public async Task<IActionResult> GetById(string reference)
    {
        var check = await _context.Checks
            .Include(c => c.Checkbook)
                .ThenInclude(cb => cb!.Bank)
            .FirstOrDefaultAsync(c => c.Reference == reference);
            
        if (check == null)
        {
            return NotFound(new { message = "Chèque non trouvé" });
        }
        
        var result = new
        {
            reference = check.Reference,
            userId = check.UserId,
            checkbookId = check.CheckbookId,
            amount = check.Amount,
            payee = check.Payee,
            city = check.City,
            bank = check.Checkbook?.Bank?.Name ?? "",
            ville = check.Ville,
            status = check.Status,
            motif = check.Motif,
            createdAt = check.CreatedAt
        };
        return Ok(result);
    }

    [HttpGet("check-reference")]
    public async Task<IActionResult> CheckReference([FromQuery] string reference)
    {
        if (string.IsNullOrWhiteSpace(reference))
        {
            return BadRequest(new { message = "Référence requise" });
        }

        var exists = await _context.Checks.AnyAsync(c => c.Reference == reference);
        return Ok(new { exists });
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CheckCreateRequest request)
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");

        string bankName = "";
        
        // Si un checkbookId est fourni, vérifier et incrémenter
        if (request.CheckbookId.HasValue)
        {
            var checkbook = await _context.Checkbooks
                .Include(cb => cb.Bank)
                .FirstOrDefaultAsync(cb => cb.Id == request.CheckbookId.Value);
                
            if (checkbook == null)
            {
                return BadRequest(new { message = "Chéquier non trouvé" });
            }

            if (checkbook.UsedCount >= checkbook.Capacity)
            {
                return BadRequest(new { message = "Chéquier complet" });
            }

            // Incrémenter le compteur
            checkbook.UsedCount++;
            
            // Récupérer le nom de la banque
            bankName = checkbook.Bank?.Name ?? "";
        }

        var check = new Check
        {
            Reference = request.Reference,
            UserId = userId,
            CheckbookId = request.CheckbookId,
            Amount = request.Amount,
            Payee = request.Payee,
            City = request.City,
            Date = request.Date,
            Ville = request.Ville ?? string.Empty
        };

        var createdCheck = await _checkService.CreateCheckAsync(check);

        // Log the action
        await _auditService.LogAction(userId, "PRINT_CHECK", "Check", null, new
        {
            amount = createdCheck.Amount,
            payee = createdCheck.Payee,
            bank = bankName,
            ville = createdCheck.Ville,
            reference = createdCheck.Reference,
            checkbookId = createdCheck.CheckbookId
        });

        var result = new
        {
            reference = createdCheck.Reference,
            userId = createdCheck.UserId,
            checkbookId = createdCheck.CheckbookId,
            amount = createdCheck.Amount,
            payee = createdCheck.Payee,
            city = createdCheck.City,
            date = createdCheck.Date,
            bank = bankName,
            ville = createdCheck.Ville,
            status = createdCheck.Status,
            motif = createdCheck.Motif,
            createdAt = createdCheck.CreatedAt
        };

        await _hubContext.Clients.All.SendAsync("checkCreated", result);
        return CreatedAtAction(nameof(GetById), new { reference = createdCheck.Reference }, result);
    }

    [HttpPatch("{reference}/status")]
    public async Task<IActionResult> UpdateStatus(string reference, [FromBody] UpdateStatusRequest request)
    {
        try
        {
            var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
            Console.WriteLine($"[UpdateStatus] User {userId} updating check {reference} to status '{request.Status}' with motif '{request.Motif}'");
            
            var check = await _checkService.UpdateCheckStatusAsync(reference, request.Status, request.Motif);
            
            if (check == null)
            {
                Console.WriteLine($"[UpdateStatus] Check {reference} not found");
                return NotFound(new { message = "Chèque non trouvé" });
            }
            
            Console.WriteLine($"[UpdateStatus] Check {reference} status updated successfully to '{check.Status}'");

            // Charger le chéquier et la banque
            var checkWithBank = await _context.Checks
                .Include(c => c.Checkbook)
                    .ThenInclude(cb => cb!.Bank)
                .FirstOrDefaultAsync(c => c.Reference == reference);

            // Log the action
            await _auditService.LogAction(userId, "UPDATE_CHECK_STATUS", "Check", null, new
            {
                reference = check.Reference,
                newStatus = check.Status,
                motif = check.Motif,
                amount = check.Amount,
                payee = check.Payee
            });

            var result = new
            {
                reference = check.Reference,
                userId = check.UserId,
                amount = check.Amount,
                payee = check.Payee,
                city = check.City,
                date = check.Date,
                bank = checkWithBank?.Checkbook?.Bank?.Name ?? "",
                ville = check.Ville,
                status = check.Status,
                motif = check.Motif,
                createdAt = check.CreatedAt
            };

            await _hubContext.Clients.All.SendAsync("checkStatusUpdated", result);
            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"[UpdateStatus] ArgumentException: {ex.Message}");
            return BadRequest(new { message = ex.Message });
        }
        catch (InvalidOperationException ex)
        {
            Console.WriteLine($"[UpdateStatus] InvalidOperationException: {ex.Message}");
            return BadRequest(new { message = ex.Message });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[UpdateStatus] Unexpected error: {ex.Message}\n{ex.StackTrace}");
            return StatusCode(500, new { message = "Erreur serveur lors de la mise à jour du statut" });
        }
    }

    [HttpGet("stats")]
    public async Task<IActionResult> GetStats()
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
        var user = await _context.Users.FindAsync(userId);
        
        if (user == null)
            return Unauthorized();

        // If regionale, calculate stats only for checks from users of the same region
        if (user.Role == "regionale" && !string.IsNullOrEmpty(user.Region))
        {
            var regionUserIds = await _context.Users
                .Where(u => u.Role == "regionale" && u.Region == user.Region)
                .Select(u => u.Id)
                .ToListAsync();
            var filteredChecks = await _context.Checks
                .Where(c => regionUserIds.Contains(c.UserId))
                .ToListAsync();

            var totalAmount = filteredChecks.Sum(c => c.Amount);
            var totalCount = filteredChecks.Count;
            var currentMonth = DateTime.UtcNow.Month;
            var currentYear = DateTime.UtcNow.Year;
            var monthlyCount = filteredChecks.Count(c => c.CreatedAt.Month == currentMonth && c.CreatedAt.Year == currentYear);

            return Ok(new { totalAmount, totalCount, monthlyCount });
        }

        var stats = await _checkService.GetStatsAsync();
        return Ok(stats);
    }

    [HttpPost("log-export")]
    public async Task<IActionResult> LogExport([FromBody] LogExportRequest request)
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");

        await _auditService.LogAction(
            userId,
            "EXPORT_HISTORY",
            "Check",
            null,
            new
            {
                format = request.Format,
                recordCount = request.RecordCount,
                dateRange = request.DateRange
            }
        );

        return Ok(new { message = "Export enregistré" });
    }
}

public record CheckCreateRequest(
    decimal Amount,
    string Payee,
    string City,
    string Date,
    string Reference,
    string Bank,
    string? Ville,
    int? CheckbookId
);

public record UpdateStatusRequest(
    string Status,
    string? Motif
);

public record LogExportRequest(
    string Format,
    int RecordCount,
    string? DateRange
);

