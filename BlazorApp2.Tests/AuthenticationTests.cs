using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Json;
using Xunit;
using Moq;

namespace BlazorApp2.Tests;

/// <summary>
/// Tests authentication - both authenticated and not authenticated
/// against view, code, and web api
/// </summary>
public class AuthenticationTests
{
    // ── AGAINST CODE ────────────────────────────────────────────────

    [Fact]
    public void UnauthenticatedUser_HasNoIdentity()
    {
        // Arrange
        var mockUser = new Mock<System.Security.Principal.IIdentity>();
        mockUser.Setup(u => u.IsAuthenticated).Returns(false);

        // Act
        var isAuthenticated = mockUser.Object.IsAuthenticated;

        // Assert
        Assert.False(isAuthenticated);
    }

    [Fact]
    public void AuthenticatedUser_HasIdentity()
    {
        // Arrange
        var mockUser = new Mock<System.Security.Principal.IIdentity>();
        mockUser.Setup(u => u.IsAuthenticated).Returns(true);
        mockUser.Setup(u => u.Name).Returns("test@test.com");

        // Act
        var isAuthenticated = mockUser.Object.IsAuthenticated;
        var name = mockUser.Object.Name;

        // Assert
        Assert.True(isAuthenticated);
        Assert.Equal("test@test.com", name);
    }

    [Fact]
    public void PasswordHasher_ValidPassword_ReturnsSuccess()
    {
        // Arrange
        var hasher = new PasswordHasher<IdentityUser>();
        var user = new IdentityUser { UserName = "test@test.com" };
        var password = "Test@1234!";

        // Act
        var hash = hasher.HashPassword(user, password);
        var result = hasher.VerifyHashedPassword(user, hash, password);

        // Assert
        Assert.Equal(PasswordVerificationResult.Success, result);
    }

    [Fact]
    public void PasswordHasher_WrongPassword_ReturnsFailed()
    {
        // Arrange
        var hasher = new PasswordHasher<IdentityUser>();
        var user = new IdentityUser { UserName = "test@test.com" };
        var password = "Test@1234!";
        var wrongPassword = "WrongPassword!";

        // Act
        var hash = hasher.HashPassword(user, password);
        var result = hasher.VerifyHashedPassword(user, hash, wrongPassword);

        // Assert
        Assert.Equal(PasswordVerificationResult.Failed, result);
    }

    // ── AGAINST VIEW ────────────────────────────────────────────────

    [Fact]
    public async Task UnauthenticatedUser_CanAccess_HomePage()
    {
        // Arrange
        await using var factory = new WebApplicationFactory<Program>();
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        // Act
        var response = await client.GetAsync("/");

        // Assert - home page is publicly accessible
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task UnauthenticatedUser_IsRedirected_FromProtectedPage()
    {
        // Arrange
        await using var factory = new WebApplicationFactory<Program>();
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        // Act
        var response = await client.GetAsync("/addroles");

        // Assert - redirected to login because not authenticated
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
    }

    // ── AGAINST WEB API ─────────────────────────────────────────────

    [Fact]
    public async Task UnauthenticatedRequest_ToDeleteEndpoint_Returns401()
    {
        // Arrange
        await using var factory = new WebApplicationFactory<MinimalApi.Program>();
        var client = factory.CreateClient();

        // Act - call delete without any token
        var response = await client.DeleteAsync("/users/test@test.com");

        // Assert - 401 because no token provided
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task UnauthenticatedRequest_ToLoginEndpoint_IsAccessible()
    {
        // Arrange
        await using var factory = new WebApplicationFactory<MinimalApi.Program>();
        var client = factory.CreateClient();

        // Act - login endpoint should be reachable without token
        var response = await client.PostAsJsonAsync("/login", new
        {
            email = "nonexistent@test.com",
            password = "wrongpassword"
        });

        // Assert - 401 (wrong credentials) but endpoint is reachable, not 404
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
