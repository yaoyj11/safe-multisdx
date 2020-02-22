import("../stitch-all.slang").
//cannot use as tag here

defcon routeTagAclEntry(?Tag,?Prefix) :-
  spec("user as tag access control list"),
  {
    routeTagAclEntry($Tag,$Prefix).
    label("routeTagAclEntry($Prefix)($Version)").
  }.

defpost postASTagAclEntry(?Tag,?Prefix) :- [routeTagAclEntry(?Tag,?Prefix)].

defcon routeTagAclEntrySD(?Tag, ?SrcIP, ?DstIP) :-
  spec("user as tag access control list"),
  {
    routeTagAclEntry($Tag, $SrcIP, $DstIP).
    label("routeTagAclEntry($SrcIP)($DstIP)($Version)").
  }.

defcon sdPolicySet(?SrcPrefix,?DstPrefix) :-
  ?TagAclToken := label("routeTagAclEntry(?SrcPrefix)(?DstPrefix)($Version)"),
  ?IPToken := label("Token for IP allocation/?SrcPrefix($Version)"),
  ?AuthASPolicy := label("authz as policy($PolicyVersion)"),
  ?TagPrivPolicy := label("tag-access-policy($PolicyVersion)"),
  {
    link($IPToken).
    link($TagAclToken).
    link($AuthASPolicy).
    link($TagPrivPolicy).
    label("SD Policy Set/$SrcPrefix/$DstPrefix($Version)").
  }.

defpost postASTagAclEntrySD(?Tag,?SrcPrefix,?DstPrefix) :- [routeTagAclEntrySD(?Tag,?SrcPrefix,?DstPrefix)].

defpost postSdPolicySet(?SrcPrefix,?DstPrefix) :- [sdPolicySet(?SrcPrefix,?DstPrefix)].

defcon authorizeASPolicy():-
  {

    authorizedAS(?AS, ?DstIP):-
      authorizedASByUserAttr(?AS, ?DstIP).

    authorizedASByUserAttr(?AS, ?Prefix):-
      routeTagAclEntry(?Tag, ?PrefixSet),
      ?Prefix <: ?PrefixSet,
      tagPrivilege(?Tag, ?AS).

    authorizedAS(?AS, ?SrcIP, ?DstIP):-
      authorizedASByUserAttr(?AS, ?SrcIP, ?DstIP).

    authorizedASByUserAttr(?AS, ?SrcIP, ?DstIP):-
      routeTagAclEntry(?Tag, ?SrcPrefix, ?DstPrefix),
      ?SrcIP <: ?SrcPrefix,
      ?DstIP <: ?DstPrefix,
      tagPrivilege(?Tag, ?AS).

    label("authz as policy($PolicyVersion)").
  }.

defpost postAuthorizeASPolicy() :- [authorizeASPolicy()].

defcon verifyASPolicy():-
  {
     verifyAS(?Owner, ?DstIP, ?AS):-
        ?Owner: authorizedAS(?AS, ?DstIP).

     verifyAS(?Owner, ?SrcIP, ?DstIP, ?AS):-
        ?Owner: authorizedAS(?AS, ?SrcIP, ?DstIP).

     label("verify as policy($PolicyVersion)").
  }.

definit verifyASPolicy().

defpost postVerifyASPolicy() :- [verifyASPolicy()].

defcon routingPolicy() :-
  {
    route(?Owner,?DstIP,?Path) :-
      authorizedAdvertise(?Owner,?DstIP,?Path,$Self).

    authorizedAdvertise(?Owner,?DstIP,?Path,?AS):-
      eq([?Owner|?Tail],?Path),
      eq(?Tail,[]),
      ?Owner: advertise(?DstIP,?Path,?AS),
      ownPrefix(?Owner,?SupDstIP),
      ?DstIP <: ?SupDstIP.

    authorizedAdvertise(?Owner,?DstIP,?Path,?AS):-
      eq([?Head|?Tail],?Path),
      ?Head:advertise(?DstIP,?Path,?AS),
      ?Owner: authorizedAS(?Head, ?DstIP),
      authorizedAdvertise(?Owner,?DstIP,?Tail,?Head).

    route(?Owner,?SrcIP,?DstIP,?Path) :-
      authorizedAdvertise(?Owner,?SrcIP,?DstIP,?Path,$Self).

    authorizedAdvertise(?Owner,?SrcIP,?DstIP,?Path,?AS):-
      eq([?Owner|?Tail],?Path),
      eq(?Tail,[]),
      ?Owner: advertise(?SrcIP,?DstIP,?Path,?AS),
      ownPrefix(?Owner,?SupDstIP),
      ?DstIP <: ?SupDstIP.

    authorizedAdvertise(?Owner,?SrcIP,?DstIP,?Path,?AS):-
      eq([?Head|?Tail],?Path),
      ?Head:advertise(?SrcIP,?DstIP,?Path,?AS),
      ?Owner: authorizedAS(?Head,?SrcIP,?DstIP),
      authorizedAdvertise(?Owner,?SrcIP,?DstIP,?Tail,?Head).

    compliantPath(?Owner,?SrcIP,?DstIP,?Path) :-
      eq([?Owner|?Tail],?Path),
      eq(?Tail,[]),
      ownPrefix(?Owner, ?SupDstIP),
      ?DstIP <: ?SupDstIP.

    compliantPath(?Owner,?SrcIP,?DstIP,?Path) :-
      eq([?Owner|?Tail],?Path),
      compliantPath(?Owner, ?SrcIP, ?DstIP, ?Tail).

    compliantPath(?Owner, ?SrcIP, ?DstIP, ?Path) :-
      eq([?Head|?Tail],?Path),
      eq(?Tail,[]),
      ?Owner: authorizedAS(?Head, ?SrcIP, ?DstIP).

    compliantPath(?Owner, ?SrcIP, ?DstIP, ?Path) :-
      eq([?Head|?Tail],?Path),
      ?Owner: authorizedAS(?Head, ?SrcIP, ?DstIP),
      compliantPath(?Owner, ?SrcIP, ?DstIP, ?Tail).

    label("routing policy($PolicyVersion)").
  }.

defpost postRoutingPolicy() :- [routingPolicy()].
definit routingPolicy().

defcon advertiseRoute(?DstIP,?Path,?Target,?Source,?Len):-
  ?PathToken := label("Path/?Source/?DstIP/?Len ($Version)"),
  ?TagSubjectSet := label("tags($Version)"),
  {
    link($PathToken).
    link($TagSubjectSet).
    advertise($DstIP,$Path,$Target).
    label("Advertise/$Target/$DstIP/$Len ($Version)").
  }.

defpost postAdvertise(?DstIP,?Path,?Target,?Source,?Len):- [advertiseRoute(?DstIP,?Path,?Target,?Source,?Len)].

defcon advertiseRouteSD(?SrcIP,?DstIP,?Path,?Target,?Source,?Len):-
  ?PathToken := label("Path/?Source/?SrcIP/?DstIP/?Len ($Version)"),
  ?TagSubjectSet := label("tags($Version)"),
  {
    link($PathToken).
    link($TagSubjectSet).
    advertise($SrcIP,$DstIP,$Path,$Target).
    label("Advertise/$Target/$SrcIP/$DstIP/$Len ($Version)").
  }.

defpost postAdvertiseSD(?SrcIP,?DstIP,?Path,?Target,?Source,?Len):- [advertiseRouteSD(?SrcIP,?DstIP,?Path,?Target,?Source,?Len)].

//can not use init here
defcon startRoute(?DstIP,?Path,?Target,?Len):-
  ?Token := label("Token for IP allocation/?DstIP($Version)"),
  ?AuthzASPolicy := label("authz as policy($PolicyVersion)"),
  ?AuthzASACL := label("routeTagAclEntry(?DstIP)($Version)"),
  ?TagPrivPolicy := label("tag-access-policy($PolicyVersion)"),
  {
    link($Token).
    link($AuthzASACL).
    link($AuthzASPolicy).
    link($TagPrivPolicy).
    advertise($DstIP,$Path,$Target).
    label("Advertise/$Target/$DstIP/$Len ($Version)").
  }.

defpost postInitRoute(?DstIP,?Path,?Target,?Len) :- [startRoute(?DstIP,?Path,?Target,?Len)].

defcon startRouteSD(?SrcIP,?DstIP,?Path,?Target,?Len):-
  ?Token := label("Token for IP allocation/?DstIP($Version)"),
  ?AuthzASPolicy := label("authz as policy($PolicyVersion)"),
  ?AuthzASACL := label("routeTagAclEntry(?SrcIP)(?DstIP)($Version)"),
  ?TagPrivPolicy := label("tag-access-policy($PolicyVersion)"),
  {
    link($Token).
    link($AuthzASACL).
    link($AuthzASPolicy).
    link($TagPrivPolicy).
    advertise($SrcIP,$DstIP,$Path,$Target).
    label("Advertise/$Target/$SrcIP/$DstIP/$Len ($Version)").
  }.

defpost postInitRouteSD(?SrcIP,?DstIP,?Path,?Target,?Len) :- [startRouteSD(?SrcIP,?DstIP,?Path,?Target,?Len)].

defcon linkRoute(?Token,?DstIP,?Src,?Len):-
  spec("link a token for an advertised path"),
  {
    link($Token).
    label("Path/$Src/$DstIP/$Len ($Version)").
  }.

defcon addTokenPerIP(?Token,?DstIP):-
  {
    link($Token).
    label("Token for IP/$DstIP ($Version)").
  }.


defpost postPathToken(?Token,?DstIP,?Src,?Len) :- [linkRoute(?Token,?DstIP,?Src,?Len), addTokenPerIP(?Token,?DstIP)].

//void using Src and SrcIP at the same time, as the interpreter mistake $SrcIP for $Src + "IP"
defcon linkRouteSD(?Token,?SrcIP,?DstIP,?Source,?Len):-
  spec("link a token for an advertised path"),
  {
    link($Token).
    label("Path/$Source/$SrcIP/$DstIP/$Len ($Version)").
  }.

defcon addTokenPerIPSD(?Token,?SrcIP,?DstIP):-
  {
    link($Token).
    label("Token for IP/$SrcIP/$DstIP ($Version)").
  }.


defpost postPathTokenSD(?Token,?SrcIP,?DstIP,?Source,?Len) :- [linkRouteSD(?Token,?SrcIP,?DstIP,?Source,?Len), addTokenPerIPSD(?Token,?SrcIP,?DstIP)].

defguard verifyRoute(?Owner,?DstIP,?Path,?Token) :-
  ?RoutingPolicyRef := label("routing policy($PolicyVersion)"),
  ?OwnPrefixPolicy := label("own prefix policy($PolicyVersion)"),
  {
    link($OwnPrefixPolicy).
    link($RoutingPolicyRef).
    link($Token).
    route($Owner, $DstIP,$Path)?
  }.

defguard verifyRouteSD(?Owner,?SrcIP,?DstIP,?Path,?Token) :-
  ?RoutingPolicyRef := label("routing policy($PolicyVersion)"),
  ?OwnPrefixPolicy := label("own prefix policy($PolicyVersion)"),
  {
    link($OwnPrefixPolicy).
    link($RoutingPolicyRef).
    link($Token).
    route($Owner,$SrcIP,$DstIP,$Path)?
  }.

defguard verifyCompliantPath(?Owner,?SrcIP,?DstIP,?Path,?PolicyToken, ?RouteToken) :-
  ?RoutingPolicyRef := label("routing policy($PolicyVersion)"),
  ?OwnPrefixPolicy := label("own prefix policy($PolicyVersion)"),
  ?SelfTagSet := label("tags($Version)"),
  {
    link($OwnPrefixPolicy).
    link($RoutingPolicyRef).
    link($PolicyToken).
    link($RouteToken).
    link($SelfTagSet).
    compliantPath($Owner,$SrcIP,$DstIP,$Path)?
  }.

defguard verifyAS(?Owner, ?DstIP, ?AS, ?Token):-
  ?VerifyASPolicyRef := label("verify as policy($PolicyVersion)"),
  ?ASTagSet := label(?AS, "tags($Version)"),
  {
    link($Token).
    link($VerifyASPolicyRef).
    link($ASTagSet).
    verifyAS($Owner, $DstIP, $AS)?
  }.

defguard verifyASSD(?Owner, ?SrcIP, ?DstIP, ?AS, ?Token):-
  ?VerifyASPolicyRef := label("verify as policy($PolicyVersion)"),
  ?ASTagSet := label(?AS, "tags($Version)"),
  {
    link($Token).
    link($VerifyASPolicyRef).
    link($ASTagSet).
    verifyAS($Owner, $SrcIP, $DstIP, $AS)?
  }.

