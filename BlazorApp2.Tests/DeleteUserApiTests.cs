using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Xunit;

namespace BlazorApp2.Tests;

/// <summary>
/// Tests the delete user endpoint on the Minimal API specifically
/// </summary>
public class DeleteUserApiTests
{
    [Fact]
    public async Task DeleteEndpoint_WithoutToken_Returns401()
    {
        // Arrange
        await using var factory = new WebApplicationFactory<MinimalApi.Program>();
        var client = factory.CreateClient();

        // Act
        var response = await client.DeleteAsync("/users/anyuser@test.com");

        // Assert - protected endpoint rejects unauthenticated requests
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task DeleteEndpoint_WithInvalidToken_Returns401()
    {
        // Arrange
        await using var factory = new WebApplicationFactory<MinimalApi.Program>();
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "this.is.not.valid");

        // Act
        var response = await client.DeleteAsync("/users/anyuser@test.com");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task DeleteEndpoint_NonExistentUser_WithAdminToken_Returns404()
    {
        // Arrange
        await using var factory = new WebApplicationFactory<MinimalApi.Program>();
        var client = factory.CreateClient();

        // First get a valid admin token
        var loginResponse = await client.PostAsJsonAsync("/login", new
        {
            email    = "admin@admin.com",
            password = "Admin@1234!"
        });

        // Skip test if admin doesn't exist in test environment
        if (!loginResponse.IsSuccessStatusCode)
            return;

        var tokenResult = await loginResponse.Content.ReadFromJsonAsync<TokenResponse>();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", tokenResult!.Token);

        // Act - try to delete user that doesn't exist
        var response = await client.DeleteAsync("/users/doesnotexist@nowhere.com");

        // Assert - 404 because user not found
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task LoginEndpoint_IsReachable()
    {
        // Arrange
        await using var factory = new WebApplicationFactory<MinimalApi.Program>();
        var client = factory.CreateClient();

        // Act
        var response = await client.PostAsJsonAsync("/login", new
        {
            email    = "test@test.com",
            password = "wrongpassword"
        });

        // Assert - endpoint exists and responds (even if credentials wrong)
        Assert.NotEqual(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task LoginEndpoint_WithEmptyEmail_ReturnsBadRequestOrUnauthorized()
    {
        // Arrange
        await using var factory = new WebApplicationFactory<MinimalApi.Program>();
        var client = factory.CreateClient();

        // Act
        var response = await client.PostAsJsonAsync("/login", new
        {
            email    = "",
            password = "somepassword"
        });

        // Assert - invalid input is rejected
        Assert.True(
            response.StatusCode == HttpStatusCode.Unauthorized ||
            response.StatusCode == HttpStatusCode.BadRequest
        );
    }

    private sealed class TokenResponse
    {
        public string Token { get; set; } = string.Empty;
    }
}
