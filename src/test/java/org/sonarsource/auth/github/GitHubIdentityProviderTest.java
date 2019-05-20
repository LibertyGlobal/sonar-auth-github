/*
 * GitHub Authentication for SonarQube
 * Copyright (C) 2016-2019 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonarsource.auth.github;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.sonar.api.config.internal.MapSettings;
import org.sonar.api.server.authentication.OAuth2IdentityProvider;
import org.sonarsource.auth.github.GitHubIdentityProvider.EmailSet;
import org.sonarsource.auth.github.GsonEmails.GsonEmail;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.sonarsource.auth.github.GitHubSettings.LOGIN_STRATEGY_DEFAULT_VALUE;

import java.util.ArrayList;
import java.util.List;

public class GitHubIdentityProviderTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  private MapSettings settings = new MapSettings();
  private GitHubSettings gitHubSettings = new GitHubSettings(settings);
  private UserIdentityFactoryImpl userIdentityFactory = mock(UserIdentityFactoryImpl.class);
  private ScribeGitHubApi scribeApi = new ScribeGitHubApi(gitHubSettings);
  private GitHubRestClient gitHubRestClient = new GitHubRestClient(gitHubSettings);
  private SecondaryEmailsSupplier secondaryEmailsSupplier = new SecondaryEmailsSupplier(gitHubSettings);
  private GitHubIdentityProvider underTest = new GitHubIdentityProvider(gitHubSettings, userIdentityFactory, scribeApi, gitHubRestClient, secondaryEmailsSupplier);

  @Test
  public void check_fields() {
    assertThat(underTest.getKey()).isEqualTo("github");
    assertThat(underTest.getName()).isEqualTo("GitHub");
    assertThat(underTest.getDisplay().getIconPath()).isEqualTo("/static/authgithub/github.svg");
    assertThat(underTest.getDisplay().getBackgroundColor()).isEqualTo("#444444");
  }

  @Test
  public void is_enabled() {
    settings.setProperty("sonar.auth.github.clientId.secured", "id");
    settings.setProperty("sonar.auth.github.clientSecret.secured", "secret");
    settings.setProperty("sonar.auth.github.loginStrategy", LOGIN_STRATEGY_DEFAULT_VALUE);
    settings.setProperty("sonar.auth.github.enabled", true);
    assertThat(underTest.isEnabled()).isTrue();

    settings.setProperty("sonar.auth.github.enabled", false);
    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void should_allow_users_to_signup() {
    assertThat(underTest.allowsUsersToSignUp()).as("default").isFalse();

    settings.setProperty("sonar.auth.github.allowUsersToSignUp", true);
    assertThat(underTest.allowsUsersToSignUp()).isTrue();
  }

  @Test
  public void init() {
    setSettings(true);
    OAuth2IdentityProvider.InitContext context = mock(OAuth2IdentityProvider.InitContext.class);
    when(context.generateCsrfState()).thenReturn("state");
    when(context.getCallbackUrl()).thenReturn("http://localhost/callback");
    settings.setProperty("sonar.auth.github.webUrl", "https://github.com/");

    underTest.init(context);

    verify(context).redirectTo("https://github.com/login/oauth/authorize" +
      "?response_type=code" +
      "&client_id=id" +
      "&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&scope=user%3Aemail" +
      "&state=state");
  }

  @Test
  public void init_when_group_sync() {
    setSettings(true);
    settings.setProperty("sonar.auth.github.groupsSync", "true");
    settings.setProperty("sonar.auth.github.webUrl", "https://github.com/");
    OAuth2IdentityProvider.InitContext context = mock(OAuth2IdentityProvider.InitContext.class);
    when(context.generateCsrfState()).thenReturn("state");
    when(context.getCallbackUrl()).thenReturn("http://localhost/callback");

    underTest.init(context);

    verify(context).redirectTo("https://github.com/login/oauth/authorize" +
      "?response_type=code" +
      "&client_id=id" +
      "&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&scope=user%3Aemail%2Cread%3Aorg" +
      "&state=state");
  }

  @Test
  public void init_when_organizations() {
    setSettings(true);
    settings.setProperty("sonar.auth.github.organizations", "example");
    settings.setProperty("sonar.auth.github.webUrl", "https://github.com/");
    OAuth2IdentityProvider.InitContext context = mock(OAuth2IdentityProvider.InitContext.class);
    when(context.generateCsrfState()).thenReturn("state");
    when(context.getCallbackUrl()).thenReturn("http://localhost/callback");

    underTest.init(context);

    verify(context).redirectTo("https://github.com/login/oauth/authorize" +
      "?response_type=code" +
      "&client_id=id" +
      "&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback" +
      "&scope=user%3Aemail%2Cread%3Aorg" +
      "&state=state");
  }

  @Test
  public void fail_to_init_when_disabled() {
    setSettings(false);
    OAuth2IdentityProvider.InitContext context = mock(OAuth2IdentityProvider.InitContext.class);

    thrown.expect(IllegalStateException.class);
    thrown.expectMessage("GitHub authentication is disabled");
    underTest.init(context);
  }

  @Test
  public void scope_includes_org_when_necessary() {
    setSettings(false);

    settings.setProperty("sonar.auth.github.groupsSync", false);
    settings.setProperty("sonar.auth.github.organizations", "");
    assertThat(underTest.getScope()).isEqualTo("user:email");

    settings.setProperty("sonar.auth.github.groupsSync", true);
    settings.setProperty("sonar.auth.github.organizations", "");
    assertThat(underTest.getScope()).isEqualTo("user:email,read:org");

    settings.setProperty("sonar.auth.github.groupsSync", false);
    settings.setProperty("sonar.auth.github.organizations", "example");
    assertThat(underTest.getScope()).isEqualTo("user:email,read:org");

    settings.setProperty("sonar.auth.github.groupsSync", true);
    settings.setProperty("sonar.auth.github.organizations", "example");
    assertThat(underTest.getScope()).isEqualTo("user:email,read:org");
  }

  @Test
  public void organization_membership_required() {
    setSettings(true);
    settings.setProperty("sonar.auth.github.organizations", "example");
    assertThat(underTest.isOrganizationMembershipRequired()).isTrue();
    settings.setProperty("sonar.auth.github.organizations", "example0, example1");
    assertThat(underTest.isOrganizationMembershipRequired()).isTrue();
  }

  @Test
  public void organization_membership_not_required() {
    setSettings(true);
    settings.setProperty("sonar.auth.github.organizations", "");
    assertThat(underTest.isOrganizationMembershipRequired()).isFalse();
  }

  private void setSettings(boolean enabled) {
    if (enabled) {
      settings.setProperty("sonar.auth.github.clientId.secured", "id");
      settings.setProperty("sonar.auth.github.clientSecret.secured", "secret");
      settings.setProperty("sonar.auth.github.loginStrategy", LOGIN_STRATEGY_DEFAULT_VALUE);
      settings.setProperty("sonar.auth.github.enabled", true);
    } else {
      settings.setProperty("sonar.auth.github.enabled", false);
    }
  }

  @Test
  public void emailset_just_one_from_libertyglobal() {
    List<GsonEmail> emails = new ArrayList<GsonEmails.GsonEmail>() {{
      add(new GsonEmail("vip@libertyglobal.com", true, true));
    }};
    String[] domains = { "libertyglobal.com" };
    EmailSet emailSet = GitHubIdentityProvider.getEmailSet(emails, domains);
    assertThat(emailSet.primary).isEqualTo("vip@libertyglobal.com");
    assertThat(emailSet.secondary.size()).isEqualTo(0);
  }

  @Test
  public void emailset_just_one_not_from_libertyglobal() {
    List<GsonEmail> emails = new ArrayList<GsonEmails.GsonEmail>() {{
      add(new GsonEmail("vip@google.com", true, true));
    }};
    String[] domains = { "libertyglobal.com" };
    EmailSet emailSet = GitHubIdentityProvider.getEmailSet(emails, domains);
    assertThat(emailSet.primary).isEqualTo("vip@google.com");
    assertThat(emailSet.secondary.size()).isEqualTo(0);
  }

  @Test
  public void emailset_just_one_not_primary() {
    List<GsonEmail> emails = new ArrayList<GsonEmails.GsonEmail>() {{
      add(new GsonEmail("vip@google.com", false, true));
    }};
    String[] domains = { "libertyglobal.com" };
    EmailSet emailSet = GitHubIdentityProvider.getEmailSet(emails, domains);
    assertThat(emailSet.primary).isNull();
    assertThat(emailSet.secondary.size()).isEqualTo(0);
  }

  @Test
  public void emailset_just_one_not_verified() {
    List<GsonEmail> emails = new ArrayList<GsonEmails.GsonEmail>() {{
      add(new GsonEmail("vip@google.com", true, false));
    }};
    String[] domains = { "libertyglobal.com" };
    EmailSet emailSet = GitHubIdentityProvider.getEmailSet(emails, domains);
    assertThat(emailSet.primary).isNull();
    assertThat(emailSet.secondary.size()).isEqualTo(0);
  }

  @Test
  public void emailset_libertyglobal_primary() {
    List<GsonEmail> emails = new ArrayList<GsonEmails.GsonEmail>() {{
      add(new GsonEmail("vip@libertyglobal.com", true, true));
      add(new GsonEmail("vip@google.com", true, false));
    }};
    String[] domains = { "libertyglobal.com" };
    EmailSet emailSet = GitHubIdentityProvider.getEmailSet(emails, domains);
    assertThat(emailSet.primary).isEqualTo("vip@libertyglobal.com");
    assertThat(emailSet.secondary.size()).isEqualTo(1);
    assertThat(emailSet.secondary.get(0)).isEqualTo("vip@google.com");
  }

  @Test
  public void emailset_libertyglobal_not_primary() {
    List<GsonEmail> emails = new ArrayList<GsonEmails.GsonEmail>() {{
      add(new GsonEmail("vip@google.com", true, true));
      add(new GsonEmail("vip@libertyglobal.com", true, false));
    }};
    String[] domains = { "libertyglobal.com" };
    EmailSet emailSet = GitHubIdentityProvider.getEmailSet(emails, domains);
    assertThat(emailSet.primary).isEqualTo("vip@libertyglobal.com");
    assertThat(emailSet.secondary.size()).isEqualTo(1);
    assertThat(emailSet.secondary.get(0)).isEqualTo("vip@google.com");
  }

  @Test
  public void emailset_no_libertyglobal() {
    List<GsonEmail> emails = new ArrayList<GsonEmails.GsonEmail>() {{
      add(new GsonEmail("vip@google.com", true, false));
      add(new GsonEmail("vip@apple.com", true, true));
      add(new GsonEmail("vip@microsoft.com", true, false));
    }};
    String[] domains = { "libertyglobal.com" };
    EmailSet emailSet = GitHubIdentityProvider.getEmailSet(emails, domains);
    assertThat(emailSet.primary).isEqualTo("vip@apple.com");
    assertThat(emailSet.secondary.size()).isEqualTo(2);
    assertThat(emailSet.secondary.get(0)).isEqualTo("vip@google.com");
    assertThat(emailSet.secondary.get(1)).isEqualTo("vip@microsoft.com");
  }

  @Test
  public void emailset_domains_with_blank_domain() {
    List<GsonEmail> emails = new ArrayList<GsonEmails.GsonEmail>() {{
      add(new GsonEmail("vip@google.com", true, true));
      add(new GsonEmail("vip@libertyglobal.com", true, false));
    }};
    String[] domains = { "upc.pl", "", "libertyglobal.com" };
    EmailSet emailSet = GitHubIdentityProvider.getEmailSet(emails, domains);
    assertThat(emailSet.primary).isEqualTo("vip@libertyglobal.com");
    assertThat(emailSet.secondary.size()).isEqualTo(1);
  }

  @Test
  public void emailset_no_primary_domain() {
    List<GsonEmail> emails = new ArrayList<GsonEmails.GsonEmail>() {{
      add(new GsonEmail("vip@google.com", true, false));
      add(new GsonEmail("vip@libertyglobal.com", true, true));
    }};
    String[] domains = {};
    EmailSet emailSet = GitHubIdentityProvider.getEmailSet(emails, domains);
    assertThat(emailSet.primary).isEqualTo("vip@libertyglobal.com");
    assertThat(emailSet.secondary.size()).isEqualTo(1);
  }
}
