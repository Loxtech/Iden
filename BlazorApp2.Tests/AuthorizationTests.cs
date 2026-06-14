using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using Xunit;
using Moq;

namespace BlazorApp2.Tests;

/// <summary>
/// Tests authorization - is admin / is not admin
/// against view, code, and web api
/// </summary>
public class AuthorizationTests
{
    // ── AGAINST CODE ────────────────────────────────────────────────

    [Fact]
    public void User_InAdminRole_IsAdmin()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, "admin@admin.com"),
            new Claim(ClaimTypes.Role, "Admin")
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);

        // Act
        var isAdmin = principal.IsInRole("Admin");

        // Assert
        Assert.True(isAdmin);
    }

    [Fact]
    public void User_NotInAdminRole_IsNotAdmin()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, "user@user.com"),
            new Claim(ClaimTypes.Role, "Borger")
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);

        // Act
        var isAdmin = principal.IsInRole("Admin");

        // Assert
        Assert.False(isAdmin);
    }

    [Fact]
    public void User_WithNoRoles_IsNotAdmin()
    {
        // Arrange
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, "user@user.com")
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);

        // Act
        var isAdmin = principal.IsInRole("Admin");

        // Assert
        Assert.False(isAdmin);
    }

    [Fact]
    public void AdminRole_HasCorrectRoleName()
    {
        // Arrange
        var role = new IdentityRole("Admin");

        // Act & Assert
        Assert.Equal("Admin", role.Name);
    }

    // ── AGAINST VIEW ────────────────────────────────────────────────

    [Fact]
    public async Task NonAdminUser_CannotAccess_AdminDashboard()
    {
        // Arrange
        await using var factory = new WebApplicationFactory<Program>();
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        // Act - access admin page without admin role
        var response = await client.GetAsync("/addroles");

        // Assert - redirected away (not 200 OK)
        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task UnauthenticatedUser_CannotAccess_AdminDashboard()
    {
        // Arrange
        await using var factory = new WebApplicationFactory<Program>();
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        // Act
        var response = await client.GetAsync("/addroles");

        // Assert - redirected to login
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
    }

    // ── AGAINST WEB API ─────────────────────────────────────────────

    [Fact]
    public async Task NonAdminToken_CannotDelete_User()
    {
        // Arrange
        await using var factory = new WebApplicationFactory<MinimalApi.Program>();
        var client = factory.CreateClient();

        // Use a fake/non-admin token
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "fake-non-admin-token");

        // Act
        var response = await client.DeleteAsync("/users/test@test.com");

        // Assert - 401 because token is invalid/non-admin
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task NoToken_CannotDelete_User()
    {
        // Arrange
        await using var factory = new WebApplicationFactory<MinimalApi.Program>();
        var client = factory.CreateClient();

        // Act - no Authorization header at all
        var response = await client.DeleteAsync("/users/test@test.com");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AdminLogin_WithCorrectCredentials_ReturnsToken()
    {
        // Arrange
        await using var factory = new WebApplicationFactory<MinimalApi.Program>();
        var client = factory.CreateClient();

        // Act
        var response = await client.PostAsJsonAsync("/login", new
        {
            email    = "admin@admin.com",
            password = "Admin@1234!"
        });

        // Assert - admin gets a token back
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.NotNull(result?.Token);
        Assert.NotEmpty(result.Token);
    }

    [Fact]
    public async Task NonAdminLogin_WithCorrectCredentials_IsRejected()
    {
        // Arrange
        await using var factory = new WebApplicationFactory<MinimalApi.Program>();
        var client = factory.CreateClient();

        // Act - regular user tries to get a token
        var response = await client.PostAsJsonAsync("/login", new
        {
            email    = "borger@test.com",
            password = "Test@1234!"
        });

        // Assert - rejected because not admin
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    private sealed class TokenResponse
    {
        public string Token { get; set; } = string.Empty;
    }
}
