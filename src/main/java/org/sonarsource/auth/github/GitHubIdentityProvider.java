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

import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.http.HttpServletRequest;
import org.sonar.api.server.ServerSide;
import org.sonar.api.server.authentication.Display;
import org.sonar.api.server.authentication.OAuth2IdentityProvider;
import org.sonar.api.server.authentication.UnauthorizedException;
import org.sonar.api.server.authentication.UserIdentity;
import org.sonarsource.auth.github.GsonEmails.GsonEmail;

import static java.lang.String.format;

@ServerSide
public class GitHubIdentityProvider implements OAuth2IdentityProvider {

  static final String KEY = "github";

  private final GitHubSettings settings;
  private final UserIdentityFactory userIdentityFactory;
  private final ScribeGitHubApi scribeApi;
  private final GitHubRestClient gitHubRestClient;
  private final SecondaryEmailsSupplier secondaryEmailsSupplier;

  public GitHubIdentityProvider(GitHubSettings settings, UserIdentityFactory userIdentityFactory, ScribeGitHubApi scribeApi, GitHubRestClient gitHubRestClient, SecondaryEmailsSupplier secondaryEmailsSupplier) {
    this.settings = settings;
    this.userIdentityFactory = userIdentityFactory;
    this.scribeApi = scribeApi;
    this.gitHubRestClient = gitHubRestClient;
    this.secondaryEmailsSupplier = secondaryEmailsSupplier;
  }

  @Override
  public String getKey() {
    return KEY;
  }

  @Override
  public String getName() {
    return "GitHub";
  }

  @Override
  public Display getDisplay() {
    return Display.builder()
      // URL of src/main/resources/static/github.svg at runtime
      .setIconPath("/static/authgithub/github.svg")
      .setBackgroundColor("#444444")
      .build();
  }

  @Override
  public boolean isEnabled() {
    return settings.isEnabled();
  }

  @Override
  public boolean allowsUsersToSignUp() {
    return settings.allowUsersToSignUp();
  }

  @Override
  public void init(InitContext context) {
    String state = context.generateCsrfState();
    OAuth20Service scribe = newScribeBuilder(context)
      .scope(getScope())
      .state(state)
      .build(scribeApi);
    String url = scribe.getAuthorizationUrl(/* additionalParams */ );
    context.redirectTo(url);
  }

  String getScope() {
    return (settings.syncGroups() || isOrganizationMembershipRequired()) ? "user:email,read:org" : "user:email";
  }

  @Override
  public void callback(CallbackContext context) {
    try {
      onCallback(context);
    } catch (IOException | ExecutionException e) {
      throw new IllegalStateException(e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException(e);
    }
  }

  private void onCallback(CallbackContext context) throws InterruptedException, ExecutionException, IOException {
    context.verifyCsrfState();

    HttpServletRequest request = context.getRequest();
    OAuth20Service scribe = newScribeBuilder(context).build(scribeApi);
    String code = request.getParameter("code");
    OAuth2AccessToken accessToken = scribe.getAccessToken(code);

    GsonUser user = gitHubRestClient.getUser(scribe, accessToken);
    check(scribe, accessToken, user);

    final List<GsonEmails.GsonEmail> emails = gitHubRestClient.getAllEmails(scribe, accessToken);

    final EmailSet emailSet = getEmailSet(emails);

    UserIdentity userIdentity = userIdentityFactory.create(user, emailSet.primary,
      settings.syncGroups() ? gitHubRestClient.getTeams(scribe, accessToken) : null);
    context.authenticate(userIdentity);
    context.redirectToRequestedPage();

    submitSecondaryEmails(user.getLogin(), emailSet.secondary);
  }

  boolean isOrganizationMembershipRequired() {
    return settings.organizations().length > 0;
  }

  private void check(OAuth20Service scribe, OAuth2AccessToken accessToken, GsonUser user) throws InterruptedException, ExecutionException, IOException {
    if (isUnauthorized(scribe, accessToken, user.getLogin())) {
      throw new UnauthorizedException(format("'%s' must be a member of at least one organization: '%s'", user.getLogin(), String.join("', '", settings.organizations())));
    }
  }

  private boolean isUnauthorized(OAuth20Service scribe, OAuth2AccessToken accessToken, String login) throws IOException, ExecutionException, InterruptedException {
    return isOrganizationMembershipRequired() && !isOrganizationsMember(scribe, accessToken, login);
  }

  private boolean isOrganizationsMember(OAuth20Service scribe, OAuth2AccessToken accessToken, String login) throws IOException, ExecutionException, InterruptedException {
    for (String organization : settings.organizations()) {
      if (gitHubRestClient.isOrganizationMember(scribe, accessToken, organization, login)) {
        return true;
      }
    }
    return false;
  }

  private ServiceBuilder newScribeBuilder(OAuth2IdentityProvider.OAuth2Context context) {
    if (!isEnabled()) {
      throw new IllegalStateException("GitHub authentication is disabled");
    }
    return new ServiceBuilder(settings.clientId())
      .apiSecret(settings.clientSecret())
      .callback(context.getCallbackUrl());
  }

  static final class EmailSet {
    public final String primary;
    public final List<String> secondary;

    public EmailSet(String primary, List<String> secondary) {
      this.primary = primary;
      this.secondary = secondary;
    }
  }

  /**
   * Splits email addresses obtained from GitHub into a primary one and a list
   * of secondary ones. An email address from libertyglobal.com domain is
   * always considered primary. In case such an email address is absent then
   * the email address marked as primary in GitHub is considered primary. The
   * list of secondary addresses contains the list of email addresses that are
   * not the primary one.
   *
   * @param emails
   * @return email set splitted into primary and secondary
   */
  static EmailSet getEmailSet(List<GsonEmail> emails) {
    String primary;
    List<String> secondary;

    Supplier<Stream<GsonEmail>> verifiedEmailsSupplier = () -> emails.stream().filter(email -> email.isVerified());

    String lgEmail =
        verifiedEmailsSupplier.get()
        .filter(email -> email.getEmail().endsWith("@libertyglobal.com"))
        .findFirst()
        .map(GsonEmails.GsonEmail::getEmail)
        .orElse(null);

    if (lgEmail != null) {
      primary = lgEmail;
    } else {
      primary =
          verifiedEmailsSupplier.get()
          .filter(email -> email.isPrimary())
          .findFirst()
          .map(GsonEmails.GsonEmail::getEmail)
          .orElse(null);
    }

    if (primary != null) {
      secondary =
          verifiedEmailsSupplier.get()
          .filter(email -> !email.getEmail().equals(primary))
          .map(GsonEmails.GsonEmail::getEmail)
          .collect(Collectors.toList());
    } else {
      secondary = new ArrayList<String>();
    }

    return new EmailSet(primary, secondary);
  }

  private void submitSecondaryEmails(String login, List<String> emails) {
    secondaryEmailsSupplier.update(login, emails);
  }
}
