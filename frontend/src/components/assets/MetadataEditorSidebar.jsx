import { useEffect, useState } from "react";
import Icon from "../Icon";

function parseCommaList(value) {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function normalizeTagMap(value) {
  if (!value) return {};
  if (Array.isArray(value)) {
    const payload = {};
    value.forEach((item) => {
      const text = String(item || "").trim();
      if (!text) return;
      if (text.includes("=")) {
        const [key, ...rest] = text.split("=");
        payload[key.trim()] = rest.join("=").trim();
      } else {
        payload[text] = "";
      }
    });
    return payload;
  }
  if (typeof value === "object") {
    const payload = {};
    Object.entries(value).forEach(([key, tagValue]) => {
      const normalizedKey = String(key || "").trim();
      if (!normalizedKey) return;
      payload[normalizedKey] = tagValue == null ? "" : String(tagValue).trim();
    });
    return payload;
  }
  return {};
}

function parseTagMap(value) {
  const payload = {};
  value
    .split(/[\n,;]+/)
    .map((item) => item.trim())
    .filter(Boolean)
    .forEach((entry) => {
      if (entry.includes("=")) {
        const [key, ...rest] = entry.split("=");
        const normalizedKey = key.trim();
        if (!normalizedKey) return;
        payload[normalizedKey] = rest.join("=").trim();
      } else if (entry.includes(":")) {
        const [key, ...rest] = entry.split(":");
        const normalizedKey = key.trim();
        if (!normalizedKey) return;
        payload[normalizedKey] = rest.join(":").trim();
      } else {
        payload[entry] = "";
      }
    });
  return payload;
}

function formatTagMap(value) {
  const entries = Object.entries(normalizeTagMap(value));
  if (entries.length === 0) return "";
  return entries.map(([key, tagValue]) => (tagValue ? `${key}=${tagValue}` : key)).join(", ");
}

function parseCidrList(value) {
  return value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseBulkAssetImport(value) {
  const lines = value.split(/\r?\n/);
  const items = [];
  const validKinds = new Set(["INSTANCE", "ENI", "ON_PREM", "UNKNOWN"]);

  for (let i = 0; i < lines.length; i += 1) {
    const rawLine = lines[i].trim();
    if (!rawLine || rawLine.startsWith("#")) continue;

    let ipAddress = "";
    const item = {};

    if (rawLine.includes("|")) {
      const columns = rawLine.split("|").map((part) => part.trim());
      ipAddress = columns[0] || "";
      const instanceId = columns[1] || "";
      const name = columns[2] || "";
      const instanceType = columns[3] || "";
      const state = columns[4] || "";
      const region = columns[5] || "";
      const availabilityZone = columns[6] || "";
      const accountOwner = columns[7] || "";
      const interfaceId = columns[8] || "";
      const assetKind = (columns[9] || "").toUpperCase();
      const tagsPart = columns[10] || "";
      const provider = columns[11] || "";
      const notes = columns.slice(12).join(" | ").trim();

      if (instanceId) item.instance_id = instanceId;
      if (name) item.name = name;
      if (instanceType) item.instance_type = instanceType;
      if (state) item.state = state;
      if (region) item.region = region;
      if (availabilityZone) item.availability_zone = availabilityZone;
      if (accountOwner) item.account_owner = accountOwner;
      if (interfaceId) item.interface_id = interfaceId;
      if (validKinds.has(assetKind)) item.asset_kind = assetKind;
      const tags = parseTagMap(tagsPart);
      if (Object.keys(tags).length > 0) item.tags = tags;
      if (provider) item.provider = provider;
      if (notes) item.attributes = { notes };
    } else {
      const parts = rawLine.split(",").map((part) => part.trim());
      ipAddress = parts[0];
      if (parts[1]) item.name = parts[1];
      const candidateKind = (parts[3] || "").toUpperCase();
      if (parts[3] && validKinds.has(candidateKind)) {
        if (parts[2]) item.account_owner = parts[2];
        item.asset_kind = candidateKind;
        if (parts[4]) item.tags = parseTagMap(parts.slice(4).join(","));
      } else {
        if (parts[2]) item.provider = parts[2];
        if (parts[3]) item.tags = parseTagMap(parts.slice(3).join(","));
      }
    }

    if (!ipAddress) {
      throw new Error(`Asset import line ${i + 1}: missing IP address.`);
    }

    item.ip_address = ipAddress;
    items.push(item);
  }

  if (items.length === 0) {
    throw new Error("No asset rows found to import.");
  }
  return items;
}

function parseBulkGroupImport(value, kind) {
  const lines = value.split(/\r?\n/);
  const items = [];
  const validKinds = new Set(["VPC", "CONTAINER", "EXTERNAL", "CUSTOM"]);

  for (let i = 0; i < lines.length; i += 1) {
    const rawLine = lines[i].trim();
    if (!rawLine || rawLine.startsWith("#")) continue;

    let name = "";
    let cidrPart = "";
    let explicitKind = "";
    let tagsPart = "";
    let description = "";

    if (rawLine.includes("|")) {
      const columns = rawLine.split("|").map((part) => part.trim());
      name = columns[0] || "";
      cidrPart = columns[1] || "";
      explicitKind = (columns[2] || "").toUpperCase();
      tagsPart = columns[3] || "";
      description = columns.slice(4).join(" | ").trim();
    } else {
      if (rawLine.includes("=")) {
        const splitIndex = rawLine.indexOf("=");
        name = rawLine.slice(0, splitIndex).trim();
        cidrPart = rawLine.slice(splitIndex + 1).trim();
      } else {
        const commaParts = rawLine.split(",").map((item) => item.trim()).filter(Boolean);
        if (commaParts.length > 1) {
          name = commaParts[0];
          cidrPart = commaParts.slice(1).join(",");
        } else {
          const spaceParts = rawLine.split(/\s+/).map((item) => item.trim()).filter(Boolean);
          if (spaceParts.length > 1) {
            name = spaceParts[0];
            cidrPart = spaceParts.slice(1).join(",");
          }
        }
      }

      explicitKind = kind;
    }

    if (!name) {
      throw new Error(`Group import line ${i + 1}: missing group name.`);
    }

    const cidrs = cidrPart
      .split(/[,\s]+/)
      .map((item) => item.trim())
      .filter(Boolean);
    if (cidrs.length === 0) {
      throw new Error(`Group import line ${i + 1}: missing CIDR values.`);
    }

    const normalizedKind = validKinds.has(explicitKind) ? explicitKind : kind;
    if (!validKinds.has(normalizedKind)) {
      throw new Error(
        `Group import line ${i + 1}: unsupported kind '${explicitKind}'. Use VPC, CONTAINER, EXTERNAL, or CUSTOM.`
      );
    }

    const payload = {
      name,
      kind: normalizedKind,
      cidrs,
    };

    const tags = tagsPart
      .split(/[;,]/)
      .map((item) => item.trim())
      .filter(Boolean);
    if (tags.length > 0) {
      payload.tags = tags;
    }
    if (description) {
      payload.description = description;
    }

    items.push(payload);
  }

  if (items.length === 0) {
    throw new Error("No group rows found to import.");
  }
  return items;
}

export default function MetadataEditorSidebar({
  asset,
  seedAsset,
  onClearSelection,
  groups = [],
  onSave,
  onDelete,
  onCreateNew,
  onImportAssets,
  onCreateGroup,
  onUpdateGroup,
  onDeleteGroup,
  onImportGroups,
}) {
  const [name, setName] = useState("");
  const [ipAddress, setIpAddress] = useState("");
  const [assetKind, setAssetKind] = useState("UNKNOWN");
  const [instanceId, setInstanceId] = useState("");
  const [interfaceId, setInterfaceId] = useState("");
  const [instanceType, setInstanceType] = useState("");
  const [assetState, setAssetState] = useState("");
  const [region, setRegion] = useState("");
  const [availabilityZone, setAvailabilityZone] = useState("");
  const [accountOwner, setAccountOwner] = useState("");
  const [provider, setProvider] = useState("");
  const [tags, setTags] = useState("");
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [groupName, setGroupName] = useState("");
  const [groupKind, setGroupKind] = useState("CUSTOM");
  const [groupCidrs, setGroupCidrs] = useState("");
  const [groupTags, setGroupTags] = useState("");
  const [groupDescription, setGroupDescription] = useState("");
  const [selectedGroupId, setSelectedGroupId] = useState("");
  const [groupSaving, setGroupSaving] = useState(false);
  const [groupError, setGroupError] = useState("");
  const [groupSuccess, setGroupSuccess] = useState("");
  const [assetImportText, setAssetImportText] = useState("");
  const [assetImportSaving, setAssetImportSaving] = useState(false);
  const [assetImportError, setAssetImportError] = useState("");
  const [assetImportSuccess, setAssetImportSuccess] = useState("");
  const [groupImportKind, setGroupImportKind] = useState("CONTAINER");
  const [groupImportText, setGroupImportText] = useState("");
  const [groupImportSaving, setGroupImportSaving] = useState(false);
  const [groupImportError, setGroupImportError] = useState("");
  const [groupImportSuccess, setGroupImportSuccess] = useState("");

  const isEditing = asset?.id != null;

  useEffect(() => {
    if (asset) {
      setIpAddress(asset.ip_address || "");
      setName(asset.name || "");
      setAssetKind(asset.asset_kind || "UNKNOWN");
      setInstanceId(asset.instance_id || "");
      setInterfaceId(asset.interface_id || "");
      setInstanceType(asset.instance_type || "");
      setAssetState(asset.state || "");
      setRegion(asset.region || "");
      setAvailabilityZone(asset.availability_zone || "");
      setAccountOwner(asset.account_owner || "");
      setProvider(asset.provider || "");
      setTags(formatTagMap(asset.tags));
      setNotes(asset.attributes?.notes || "");
      setError("");
      return;
    }
    if (seedAsset) {
      setIpAddress(seedAsset.ip_address || "");
      setName(seedAsset.name || "");
      setAssetKind(seedAsset.asset_kind || "UNKNOWN");
      setInstanceId(seedAsset.instance_id || "");
      setInterfaceId(seedAsset.interface_id || "");
      setInstanceType(seedAsset.instance_type || "");
      setAssetState(seedAsset.state || "");
      setRegion(seedAsset.region || "");
      setAvailabilityZone(seedAsset.availability_zone || "");
      setAccountOwner(seedAsset.account_owner || "");
      setProvider(seedAsset.provider || "");
      setTags(formatTagMap(seedAsset.tags));
      setNotes(seedAsset.attributes?.notes || "");
      setError("");
      return;
    }
    resetForm();
  }, [asset, seedAsset]);

  function resetForm() {
    setIpAddress("");
    setName("");
    setAssetKind("UNKNOWN");
    setInstanceId("");
    setInterfaceId("");
    setInstanceType("");
    setAssetState("");
    setRegion("");
    setAvailabilityZone("");
    setAccountOwner("");
    setProvider("");
    setTags("");
    setNotes("");
    setError("");
  }

  function handleSwitchToCreate() {
    onClearSelection?.();
    resetForm();
  }

  async function handleSave(e) {
    e.preventDefault();
    setSaving(true);
    setError("");
    try {
      const normalizedIp = isEditing ? asset.ip_address : ipAddress.trim();
      if (!normalizedIp) {
        throw new Error("IP address is required.");
      }
      const payload = {
        ip_address: normalizedIp,
        name: name.trim(),
        asset_kind: assetKind,
        instance_id: instanceId.trim(),
        interface_id: interfaceId.trim(),
        instance_type: instanceType.trim(),
        state: assetState.trim(),
        region: region.trim(),
        availability_zone: availabilityZone.trim(),
        account_owner: accountOwner.trim(),
        provider: provider.trim(),
        tags: parseTagMap(tags),
        attributes: notes.trim() ? { notes: notes.trim() } : {},
      };
      if (isEditing) {
        await onSave(asset.id, payload);
      } else {
        await onCreateNew(payload);
      }
      if (!isEditing) resetForm();
    } catch (err) {
      setError(err.message || "Save failed");
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (!asset?.id) return;
    setSaving(true);
    try {
      await onDelete(asset.id);
    } catch (err) {
      setError(err.message || "Delete failed");
    } finally {
      setSaving(false);
    }
  }

  function fillGroupForm(group) {
    if (!group) return;
    const cidrs = Array.isArray(group.cidrs) && group.cidrs.length
      ? group.cidrs
      : group.cidr
        ? [group.cidr]
        : [];
    setSelectedGroupId(String(group.id));
    setGroupName(group.name || "");
    setGroupKind(group.kind || "CUSTOM");
    setGroupCidrs(cidrs.join("\n"));
    setGroupTags((group.tags || []).join(", "));
    setGroupDescription(group.description || "");
    setGroupError("");
    setGroupSuccess("");
  }

  function resetGroupForm() {
    setSelectedGroupId("");
    setGroupName("");
    setGroupKind("CUSTOM");
    setGroupCidrs("");
    setGroupTags("");
    setGroupDescription("");
    setGroupError("");
    setGroupSuccess("");
  }

  useEffect(() => {
    if (!selectedGroupId) return;
    const selectedGroup = groups.find((group) => String(group.id) === selectedGroupId);
    if (!selectedGroup) {
      resetGroupForm();
      return;
    }
    fillGroupForm(selectedGroup);
  }, [groups, selectedGroupId]);

  async function handleSaveGroup(e) {
    e.preventDefault();
    if (!selectedGroupId && !onCreateGroup) return;
    if (selectedGroupId && !onUpdateGroup) return;

    setGroupSaving(true);
    setGroupError("");
    setGroupSuccess("");
    try {
      const normalizedName = groupName.trim();
      if (!normalizedName) {
        throw new Error("Group name is required.");
      }

      const cidrs = parseCidrList(groupCidrs);
      if (cidrs.length === 0) {
        throw new Error("Provide at least one CIDR.");
      }

      const payload = {
        name: normalizedName,
        kind: groupKind,
        cidrs,
      };

      const normalizedTags = parseCommaList(groupTags);
      if (normalizedTags.length > 0) {
        payload.tags = normalizedTags;
      }

      const description = groupDescription.trim();
      if (description) {
        payload.description = description;
      }

      if (selectedGroupId) {
        await onUpdateGroup(selectedGroupId, payload);
        setGroupSuccess("Group updated.");
      } else {
        await onCreateGroup(payload);
        resetGroupForm();
        setGroupSuccess("Group created.");
      }
    } catch (err) {
      setGroupError(err.message || `Failed to ${selectedGroupId ? "update" : "create"} group`);
    } finally {
      setGroupSaving(false);
    }
  }

  async function handleDeleteGroup() {
    if (!selectedGroupId || !onDeleteGroup) return;
    if (!window.confirm("Delete this network group?")) return;

    setGroupSaving(true);
    setGroupError("");
    setGroupSuccess("");
    try {
      await onDeleteGroup(selectedGroupId);
      resetGroupForm();
      setGroupSuccess("Group deleted.");
    } catch (err) {
      setGroupError(err.message || "Failed to delete group");
    } finally {
      setGroupSaving(false);
    }
  }

  async function handleImportAssetsSubmit(e) {
    e.preventDefault();
    if (!onImportAssets) return;

    setAssetImportSaving(true);
    setAssetImportError("");
    setAssetImportSuccess("");
    try {
      const items = parseBulkAssetImport(assetImportText);
      const result = await onImportAssets(items);
      setAssetImportSuccess(
        `Imported ${items.length} assets (${result?.created ?? 0} created, ${result?.updated ?? 0} updated).`
      );
      setAssetImportText("");
    } catch (err) {
      setAssetImportError(err.message || "Failed to import assets");
    } finally {
      setAssetImportSaving(false);
    }
  }

  async function handleImportGroupsSubmit(e) {
    e.preventDefault();
    if (!onImportGroups) return;

    setGroupImportSaving(true);
    setGroupImportError("");
    setGroupImportSuccess("");
    try {
      const items = parseBulkGroupImport(groupImportText, groupImportKind);
      const result = await onImportGroups(items);
      setGroupImportSuccess(
        `Imported ${items.length} groups (${result?.created ?? 0} created, ${result?.updated ?? 0} updated).`
      );
      setGroupImportText("");
    } catch (err) {
      setGroupImportError(err.message || "Failed to import groups");
    } finally {
      setGroupImportSaving(false);
    }
  }

  const inputClass =
    "bg-neutral-light/50 border border-neutral-200 rounded-lg px-3 py-1.5 text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-primary disabled:opacity-50";

  return (
    <aside className="w-72 shrink-0 bg-white border-l border-neutral-200 overflow-y-auto p-4 flex flex-col gap-4">
      <section className="flex flex-col gap-3">
        <h3 className="text-sm font-semibold text-slate-900">
          {isEditing ? "Edit Asset" : "Add New Asset"}
        </h3>
        {!isEditing && seedAsset && (
          <p className="text-[11px] text-slate-500">
            Observed from flow logs. Save to persist as asset metadata.
          </p>
        )}

        <form onSubmit={handleSave} className="flex flex-col gap-3">
          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500 font-medium">IP Address</span>
            <input
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              placeholder="10.0.1.10"
              required
              disabled={isEditing}
              className={inputClass}
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500 font-medium">Resource Name</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="payments-api"
              className={inputClass}
            />
          </label>

          <div className="grid grid-cols-2 gap-2">
            <label className="flex flex-col gap-1">
              <span className="text-xs text-slate-500 font-medium">Asset Kind</span>
              <select
                value={assetKind}
                onChange={(e) => setAssetKind(e.target.value)}
                className={inputClass}
              >
                <option value="UNKNOWN">Unknown</option>
                <option value="INSTANCE">Instance</option>
                <option value="ENI">ENI</option>
                <option value="ON_PREM">On-Prem</option>
              </select>
            </label>

            <label className="flex flex-col gap-1">
              <span className="text-xs text-slate-500 font-medium">State</span>
              <input
                value={assetState}
                onChange={(e) => setAssetState(e.target.value)}
                placeholder="running"
                className={inputClass}
              />
            </label>
          </div>

          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500 font-medium">Instance ID</span>
            <input
              value={instanceId}
              onChange={(e) => setInstanceId(e.target.value)}
              placeholder="i-0123456789abcdef0"
              className={inputClass}
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500 font-medium">ENI ID</span>
            <input
              value={interfaceId}
              onChange={(e) => setInterfaceId(e.target.value)}
              placeholder="eni-0123456789abcdef0"
              className={inputClass}
            />
          </label>

          <div className="grid grid-cols-2 gap-2">
            <label className="flex flex-col gap-1">
              <span className="text-xs text-slate-500 font-medium">Instance Type</span>
              <input
                value={instanceType}
                onChange={(e) => setInstanceType(e.target.value)}
                placeholder="m7i.large"
                className={inputClass}
              />
            </label>

            <label className="flex flex-col gap-1">
              <span className="text-xs text-slate-500 font-medium">Owner / Account</span>
              <input
                value={accountOwner}
                onChange={(e) => setAccountOwner(e.target.value)}
                placeholder="security-prod-account"
                className={inputClass}
              />
            </label>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <label className="flex flex-col gap-1">
              <span className="text-xs text-slate-500 font-medium">Region</span>
              <input
                value={region}
                onChange={(e) => setRegion(e.target.value)}
                placeholder="us-east-1"
                className={inputClass}
              />
            </label>

            <label className="flex flex-col gap-1">
              <span className="text-xs text-slate-500 font-medium">AZ</span>
              <input
                value={availabilityZone}
                onChange={(e) => setAvailabilityZone(e.target.value)}
                placeholder="us-east-1a"
                className={inputClass}
              />
            </label>
          </div>

          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500 font-medium">Provider / Team</span>
            <input
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              placeholder="platform-team"
              className={inputClass}
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500 font-medium">Tags (key=value)</span>
            <input
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="env=prod, app=payments"
              className={inputClass}
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500 font-medium">Notes</span>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={3}
              placeholder="Internal notes..."
              className={`${inputClass} resize-none`}
            />
          </label>

          {error && <p className="text-xs text-danger">{error}</p>}

          <div className="flex gap-2 mt-1">
            <button
              type="submit"
              disabled={saving}
              className="flex-1 bg-primary hover:bg-primary-dark text-white font-semibold py-2 rounded-lg text-sm transition-colors disabled:opacity-50 shadow-lg shadow-primary/20"
            >
              {saving ? "Saving..." : "Save"}
            </button>
            <button
              type="button"
              onClick={isEditing ? handleSwitchToCreate : resetForm}
              className="px-3 py-2 rounded-lg text-sm text-slate-600 border border-neutral-300 hover:bg-neutral-100 transition-colors"
            >
              {isEditing ? "New" : "Reset"}
            </button>
          </div>

          {isEditing && (
            <button
              type="button"
              onClick={handleDelete}
              disabled={saving}
              className="flex items-center justify-center gap-1 text-xs text-danger hover:text-red-600 transition-colors py-1"
            >
              <Icon name="delete" size={14} />
              Delete Asset
            </button>
          )}
        </form>
      </section>

      <section className="border-t border-neutral-200 pt-4 flex flex-col gap-3">
        <h3 className="text-sm font-semibold text-slate-900">Bulk Asset Import</h3>
        <p className="text-[11px] text-slate-500">
          Preferred format:{" "}
          <span className="font-mono">
            ip|instance_id|name|instance_type|state|region|az|account_owner|eni|asset_kind|tag1=v1;tag2=v2|provider|notes
          </span>
        </p>
        <p className="text-[11px] text-slate-400">
          CSV fallback is still supported: <span className="font-mono">ip,name,owner,asset_kind,tags</span>.
          Example:
          <span className="font-mono block mt-1">
            10.108.1.10|i-01|payments-api|m7i.large|running|us-east-1|us-east-1a|prod-acct|eni-01|INSTANCE|env=prod;app=payments|platform|Core API
          </span>
        </p>
        <form onSubmit={handleImportAssetsSubmit} className="flex flex-col gap-2">
          <textarea
            value={assetImportText}
            onChange={(e) => setAssetImportText(e.target.value)}
            rows={5}
            placeholder={
              "10.108.1.10|i-01|payments-api|m7i.large|running|us-east-1|us-east-1a|prod-acct|eni-01|INSTANCE|env=prod;app=payments|platform\n" +
              "10.251.10.10||onprem-db||active|||corp-dc||ON_PREM|env=prod;site=dc1"
            }
            className={`${inputClass} resize-y font-mono text-xs`}
          />
          {assetImportError && <p className="text-xs text-danger">{assetImportError}</p>}
          {assetImportSuccess && <p className="text-xs text-emerald-600">{assetImportSuccess}</p>}
          <button
            type="submit"
            disabled={assetImportSaving}
            className="bg-primary hover:bg-primary-dark text-white font-semibold py-2 rounded-lg text-sm transition-colors disabled:opacity-50"
          >
            {assetImportSaving ? "Importing..." : "Import Assets"}
          </button>
        </form>
      </section>

      <section className="border-t border-neutral-200 pt-4 flex flex-col gap-3">
        <h3 className="text-sm font-semibold text-slate-900">Network Group Definition</h3>

        <form onSubmit={handleSaveGroup} className="flex flex-col gap-3">
          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500 font-medium">Existing Group</span>
            <select
              value={selectedGroupId}
              onChange={(e) => {
                const nextId = e.target.value;
                if (!nextId) {
                  resetGroupForm();
                  return;
                }
                const selectedGroup = groups.find((group) => String(group.id) === nextId);
                if (selectedGroup) {
                  fillGroupForm(selectedGroup);
                }
              }}
              className={inputClass}
            >
              <option value="">Create new group...</option>
              {groups.map((group) => (
                <option key={group.id} value={String(group.id)}>
                  {group.name}
                </option>
              ))}
            </select>
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500 font-medium">Group Name</span>
            <input
              value={groupName}
              onChange={(e) => setGroupName(e.target.value)}
              placeholder="prod-vpc"
              required
              className={inputClass}
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500 font-medium">Kind</span>
            <select
              value={groupKind}
              onChange={(e) => setGroupKind(e.target.value)}
              className={inputClass}
            >
              <option value="VPC">VPC</option>
              <option value="CONTAINER">Container</option>
              <option value="EXTERNAL">External</option>
              <option value="CUSTOM">Custom</option>
            </select>
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500 font-medium">CIDRs</span>
            <textarea
              value={groupCidrs}
              onChange={(e) => setGroupCidrs(e.target.value)}
              rows={3}
              placeholder={"10.0.0.0/16,\n10.1.0.0/16"}
              required
              className={`${inputClass} resize-y`}
            />
            <span className="text-[11px] text-slate-400">
              Comma or newline separated.
            </span>
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500 font-medium">Tags (comma-separated)</span>
            <input
              value={groupTags}
              onChange={(e) => setGroupTags(e.target.value)}
              placeholder="prod, private"
              className={inputClass}
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500 font-medium">Description</span>
            <textarea
              value={groupDescription}
              onChange={(e) => setGroupDescription(e.target.value)}
              rows={2}
              placeholder="Primary production VPC ranges"
              className={`${inputClass} resize-y`}
            />
          </label>

          {groupError && <p className="text-xs text-danger">{groupError}</p>}
          {groupSuccess && <p className="text-xs text-emerald-600">{groupSuccess}</p>}

          <div className="flex gap-2 mt-1">
            <button
              type="submit"
              disabled={groupSaving}
              className="flex-1 bg-primary hover:bg-primary-dark text-white font-semibold py-2 rounded-lg text-sm transition-colors disabled:opacity-50 shadow-lg shadow-primary/20"
            >
              {groupSaving ? "Saving..." : selectedGroupId ? "Update Group" : "Create Group"}
            </button>
            <button
              type="button"
              onClick={resetGroupForm}
              className="px-3 py-2 rounded-lg text-sm text-slate-600 border border-neutral-300 hover:bg-neutral-100 transition-colors"
            >
              New
            </button>
          </div>

          {selectedGroupId && (
            <button
              type="button"
              onClick={handleDeleteGroup}
              disabled={groupSaving}
              className="flex items-center justify-center gap-1 text-xs text-danger hover:text-red-600 transition-colors py-1"
            >
              <Icon name="delete" size={14} />
              Delete Group
            </button>
          )}
        </form>
      </section>

      <section className="border-t border-neutral-200 pt-4 flex flex-col gap-3">
        <h3 className="text-sm font-semibold text-slate-900">Bulk Group Import</h3>
        <p className="text-[11px] text-slate-500">
          One line = one group. Supports:
          <span className="font-mono block mt-1">
            name | cidr1,cidr2 | kind | tag1;tag2 | description
          </span>
          <span className="font-mono block mt-1">
            name=cidr1,cidr2
          </span>
        </p>
        <form onSubmit={handleImportGroupsSubmit} className="flex flex-col gap-2">
          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500 font-medium">Default Kind</span>
            <select
              value={groupImportKind}
              onChange={(e) => setGroupImportKind(e.target.value)}
              className={inputClass}
            >
              <option value="VPC">VPC</option>
              <option value="CONTAINER">Container</option>
              <option value="EXTERNAL">External</option>
              <option value="CUSTOM">Custom</option>
            </select>
          </label>
          <textarea
            value={groupImportText}
            onChange={(e) => setGroupImportText(e.target.value)}
            rows={5}
            placeholder={
              "payments | 10.108.10.0/24,10.108.11.0/24 | CONTAINER | prod;pci | Payments app subnet\n" +
              "corp-vpc | 10.108.0.0/16 | VPC | prod | Primary VPC"
            }
            className={`${inputClass} resize-y font-mono text-xs`}
          />
          {groupImportError && <p className="text-xs text-danger">{groupImportError}</p>}
          {groupImportSuccess && <p className="text-xs text-emerald-600">{groupImportSuccess}</p>}
          <button
            type="submit"
            disabled={groupImportSaving}
            className="bg-primary hover:bg-primary-dark text-white font-semibold py-2 rounded-lg text-sm transition-colors disabled:opacity-50"
          >
            {groupImportSaving ? "Importing..." : "Import Groups"}
          </button>
        </form>
      </section>
    </aside>
  );
}
