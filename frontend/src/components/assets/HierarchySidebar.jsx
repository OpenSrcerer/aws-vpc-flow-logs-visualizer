import { useState } from "react";
import Icon from "../Icon";

function TreeNode({ label, icon, children, defaultOpen = false, group, onSelectGroup, selectedGroupId }) {
  const [open, setOpen] = useState(defaultOpen);
  const hasChildren = children && children.length > 0;
  const isSelected = group && group.id === selectedGroupId;

  const handleClick = () => {
    if (hasChildren) {
      setOpen(!open);
    } else if (onSelectGroup && group) {
      onSelectGroup(group);
    }
  };

  return (
    <div>
      <button
        onClick={handleClick}
        className={`flex items-center gap-1.5 w-full px-2 py-1 rounded text-sm transition-colors text-left ${
          isSelected
            ? "bg-primary/10 text-primary font-medium"
            : "text-slate-600 hover:text-slate-900 hover:bg-neutral-light/50"
        }`}
      >
        {hasChildren ? (
          <Icon
            name={open ? "expand_more" : "chevron_right"}
            size={16}
            className="text-slate-400 shrink-0"
          />
        ) : (
          <span className="w-4 shrink-0" />
        )}
        <Icon name={icon} size={16} className={`${isSelected ? "text-primary" : "text-slate-400"} shrink-0`} />
        <span className="truncate">{label}</span>
      </button>
      {open && hasChildren && (
        <div className="ml-4 border-l border-neutral-200 pl-1 mt-1 flex flex-col gap-0.5">
          {children.map((child, i) => (
            <TreeNode key={i} {...child} onSelectGroup={onSelectGroup} selectedGroupId={selectedGroupId} />
          ))}
        </div>
      )}
    </div>
  );
}

export default function HierarchySidebar({ groups, onSelectGroup, selectedGroupId }) {
  const tree = buildTree(groups);

  return (
    <aside className="w-56 shrink-0 bg-white border-r border-neutral-200 overflow-y-auto p-3 flex flex-col gap-2">
      <div className="flex items-center justify-between px-2 mb-1">
        <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
          Network Hierarchy
        </h3>
        {selectedGroupId && (
          <button
            onClick={() => onSelectGroup(null)}
            className="text-[10px] text-slate-400 hover:text-slate-600"
            title="Clear selection"
          >
            Clear
          </button>
        )}
      </div>

      {tree.length === 0 ? (
        <p className="text-xs text-slate-400 px-2">
          No network groups defined yet.
        </p>
      ) : (
        <div className="flex flex-col gap-1">
          {tree.map((node, i) => (
            <TreeNode key={i} {...node} onSelectGroup={onSelectGroup} selectedGroupId={selectedGroupId} />
          ))}
        </div>
      )}
    </aside>
  );
}

function buildTree(groups) {
  const byKind = {};
  for (const g of groups) {
    const k = g.kind || "CUSTOM";
    if (!byKind[k]) byKind[k] = [];
    byKind[k].push(g);
  }

  const kindIcons = {
    VPC: "cloud",
    CONTAINER: "deployed_code",
    EXTERNAL: "public",
    CUSTOM: "folder",
  };

  return Object.entries(byKind).map(([kind, items]) => ({
    label: kind,
    icon: kindIcons[kind] || "folder",
    defaultOpen: true,
    children: items.map((g) => ({
      label: `${g.name} (${formatGroupCidrs(g)})`,
      icon: "grid_view",
      group: g,
      children: [],
    })),
  }));
}

function formatGroupCidrs(group) {
  const cidrs = Array.isArray(group.cidrs) && group.cidrs.length
    ? group.cidrs
    : group.cidr
      ? [group.cidr]
      : [];

  if (cidrs.length === 0) return "no CIDR";
  if (cidrs.length <= 2) return cidrs.join(", ");
  return `${cidrs[0]}, ${cidrs[1]} (+${cidrs.length - 2})`;
}
