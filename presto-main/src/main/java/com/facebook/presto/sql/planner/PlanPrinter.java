/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.facebook.presto.sql.planner;

import com.facebook.presto.Session;
import com.facebook.presto.execution.StageInfo;
import com.facebook.presto.execution.StageStats;
import com.facebook.presto.metadata.Metadata;
import com.facebook.presto.metadata.OperatorNotFoundException;
import com.facebook.presto.metadata.Signature;
import com.facebook.presto.metadata.TableHandle;
import com.facebook.presto.metadata.TableLayout;
import com.facebook.presto.operator.OperatorStats;
import com.facebook.presto.spi.ColumnHandle;
import com.facebook.presto.spi.ConnectorTableLayoutHandle;
import com.facebook.presto.spi.predicate.Domain;
import com.facebook.presto.spi.predicate.Marker;
import com.facebook.presto.spi.predicate.Range;
import com.facebook.presto.spi.predicate.TupleDomain;
import com.facebook.presto.spi.type.Type;
import com.facebook.presto.sql.planner.PlanFragment.PlanDistribution;
import com.facebook.presto.sql.planner.plan.AggregationNode;
import com.facebook.presto.sql.planner.plan.DeleteNode;
import com.facebook.presto.sql.planner.plan.DistinctLimitNode;
import com.facebook.presto.sql.planner.plan.EnforceSingleRowNode;
import com.facebook.presto.sql.planner.plan.ExchangeNode;
import com.facebook.presto.sql.planner.plan.ExplainAnalyzeNode;
import com.facebook.presto.sql.planner.plan.FilterNode;
import com.facebook.presto.sql.planner.plan.IndexJoinNode;
import com.facebook.presto.sql.planner.plan.IndexSourceNode;
import com.facebook.presto.sql.planner.plan.JoinNode;
import com.facebook.presto.sql.planner.plan.LimitNode;
import com.facebook.presto.sql.planner.plan.MarkDistinctNode;
import com.facebook.presto.sql.planner.plan.MetadataDeleteNode;
import com.facebook.presto.sql.planner.plan.OutputNode;
import com.facebook.presto.sql.planner.plan.PlanFragmentId;
import com.facebook.presto.sql.planner.plan.PlanNode;
import com.facebook.presto.sql.planner.plan.PlanNodeId;
import com.facebook.presto.sql.planner.plan.PlanVisitor;
import com.facebook.presto.sql.planner.plan.ProjectNode;
import com.facebook.presto.sql.planner.plan.RemoteSourceNode;
import com.facebook.presto.sql.planner.plan.RowNumberNode;
import com.facebook.presto.sql.planner.plan.SampleNode;
import com.facebook.presto.sql.planner.plan.SemiJoinNode;
import com.facebook.presto.sql.planner.plan.SortNode;
import com.facebook.presto.sql.planner.plan.TableFinishNode;
import com.facebook.presto.sql.planner.plan.TableScanNode;
import com.facebook.presto.sql.planner.plan.TableWriterNode;
import com.facebook.presto.sql.planner.plan.TopNNode;
import com.facebook.presto.sql.planner.plan.TopNRowNumberNode;
import com.facebook.presto.sql.planner.plan.UnionNode;
import com.facebook.presto.sql.planner.plan.UnnestNode;
import com.facebook.presto.sql.planner.plan.ValuesNode;
import com.facebook.presto.sql.planner.plan.WindowNode;
import com.facebook.presto.sql.tree.ComparisonExpression;
import com.facebook.presto.sql.tree.Expression;
import com.facebook.presto.sql.tree.FunctionCall;
import com.facebook.presto.sql.tree.QualifiedNameReference;
import com.facebook.presto.util.GraphvizPrinter;
import com.google.common.base.Functions;
import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import io.airlift.slice.Slice;
import io.airlift.units.DataSize;
import io.airlift.units.Duration;

import java.lang.invoke.MethodHandle;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.facebook.presto.spi.type.VarcharType.VARCHAR;
import static com.facebook.presto.sql.planner.DomainUtils.simplifyDomain;
import static com.facebook.presto.util.ImmutableCollectors.toImmutableList;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkState;
import static io.airlift.units.DataSize.succinctBytes;
import static java.lang.Double.isNaN;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.stream.Collectors.toList;

public class PlanPrinter
{
    private final StringBuilder output = new StringBuilder();
    private final Metadata metadata;
    private final Optional<Map<PlanNodeId, PlanNodeStats>> stats;

    private PlanPrinter(PlanNode plan, Map<Symbol, Type> types, Metadata metadata, Session sesion)
    {
        this(plan, types, metadata, sesion, 0);
    }

    private PlanPrinter(PlanNode plan, Map<Symbol, Type> types, Metadata metadata, Session session, int indent)
    {
        requireNonNull(plan, "plan is null");
        requireNonNull(types, "types is null");
        requireNonNull(metadata, "metadata is null");

        this.metadata = metadata;
        this.stats = Optional.empty();

        Visitor visitor = new Visitor(types, session);
        plan.accept(visitor, indent);
    }

    private PlanPrinter(PlanNode plan, Map<Symbol, Type> types, Metadata metadata, Session session, Map<PlanNodeId, PlanNodeStats> stats, int indent)
    {
        requireNonNull(plan, "plan is null");
        requireNonNull(types, "types is null");
        requireNonNull(metadata, "metadata is null");

        this.metadata = metadata;
        this.stats = Optional.of(stats);

        Visitor visitor = new Visitor(types, session);
        plan.accept(visitor, indent);
    }

    @Override
    public String toString()
    {
        return output.toString();
    }

    public static String textLogicalPlan(PlanNode plan, Map<Symbol, Type> types, Metadata metadata, Session session)
    {
        return new PlanPrinter(plan, types, metadata, session).toString();
    }

    public static String textLogicalPlan(PlanNode plan, Map<Symbol, Type> types, Metadata metadata, Session session, int indent)
    {
        return new PlanPrinter(plan, types, metadata, session, indent).toString();
    }

    public static String textLogicalPlan(PlanNode plan, Map<Symbol, Type> types, Metadata metadata, Session session, Map<PlanNodeId, PlanNodeStats> stats, int indent)
    {
        return new PlanPrinter(plan, types, metadata, session, stats, indent).toString();
    }

    public static String textStagePlanWithoutStatistics(StageInfo stageInfo, Metadata metadata, Session session)
    {
        return formatFragment(metadata, session, stageInfo.getPlan(), Optional.empty(), Optional.empty());
    }

    public static String textStagePlanWithStatistics(StageInfo stageInfo, Metadata metadata, Session session)
    {
        Map<PlanNodeId, PlanNodeStats> operatorStats = new HashMap<>();
        List<OperatorStats> summaries = stageInfo.getTasks().stream()
                .flatMap(task -> task.getStats().getPipelines().stream())
                .flatMap(pipeline -> pipeline.getOperatorSummaries().stream())
                .collect(toList());
        for (OperatorStats summary : summaries) {
            operatorStats.merge(summary.getPlanNodeId(), new PlanNodeStats(summary), PlanNodeStats::merge);
        }

        return formatFragment(metadata, session, stageInfo.getPlan(), Optional.of(stageInfo.getStageStats()), Optional.of(operatorStats));
    }

    public static String textDistributedPlan(SubPlan plan, Metadata metadata, Session session)
    {
        StringBuilder builder = new StringBuilder();
        for (PlanFragment fragment : plan.getAllFragments()) {
            builder.append(formatFragment(metadata, session, fragment, Optional.empty(), Optional.empty()));
        }

        return builder.toString();
    }

    private static String formatFragment(Metadata metadata, Session session, PlanFragment fragment, Optional<StageStats> stageStats, Optional<Map<PlanNodeId, PlanNodeStats>> operatorStats)
    {
        StringBuilder builder = new StringBuilder();
        builder.append(format("Fragment %s [%s]\n",
                fragment.getId(),
                fragment.getDistribution()));

        if (stageStats.isPresent()) {
            builder.append(indentString(1))
                    .append(format("Cost: CPU %s, Input %d (%s), Output %d (%s)\n",
                            stageStats.get().getTotalCpuTime(),
                            stageStats.get().getProcessedInputPositions(),
                            stageStats.get().getProcessedInputDataSize(),
                            stageStats.get().getOutputPositions(),
                            stageStats.get().getOutputDataSize()));
        }

        builder.append(indentString(1))
                .append(format("Output layout: [%s]\n",
                        Joiner.on(", ").join(fragment.getOutputLayout())));

        if (fragment.getPartitionFunction().isPresent()) {
            PartitionFunctionBinding partitionFunction = fragment.getPartitionFunction().get();
            PartitionFunctionHandle outputPartitioning = partitionFunction.getFunctionHandle();
            boolean replicateNulls = partitionFunction.isReplicateNulls();
            List<Symbol> symbols = partitionFunction.getPartitioningColumns();
            builder.append(indentString(1));
            if (replicateNulls) {
                builder.append(format("Output partitioning: %s (replicate nulls) [%s]\n",
                        outputPartitioning,
                        Joiner.on(", ").join(symbols)));
            }
            else {
                builder.append(format("Output partitioning: %s [%s]\n",
                        outputPartitioning,
                        Joiner.on(", ").join(symbols)));
            }
        }

        if (stageStats.isPresent()) {
            builder.append(textLogicalPlan(fragment.getRoot(), fragment.getSymbols(), metadata, session, operatorStats.get(), 1))
                    .append("\n");
        }
        else {
            builder.append(textLogicalPlan(fragment.getRoot(), fragment.getSymbols(), metadata, session, 1))
                    .append("\n");
        }

        return builder.toString();
    }

    public static String graphvizLogicalPlan(PlanNode plan, Map<Symbol, Type> types)
    {
        PlanFragment fragment = new PlanFragment(
                new PlanFragmentId("graphviz_plan"),
                plan,
                types,
                plan.getOutputSymbols(),
                PlanDistribution.SINGLE,
                plan.getId(),
                Optional.empty());
        return GraphvizPrinter.printLogical(ImmutableList.of(fragment));
    }

    public static String graphvizDistributedPlan(SubPlan plan)
    {
        return GraphvizPrinter.printDistributed(plan);
    }

    private void print(int indent, String format, Object... args)
    {
        String value;

        if (args.length == 0) {
            value = format;
        }
        else {
            value = format(format, args);
        }
        output.append(indentString(indent)).append(value).append('\n');
    }

    private void print(int indent, String format, List<Object> args)
    {
        print(indent, format, args.toArray(new Object[args.size()]));
    }

    private void printStats(int intent, PlanNodeId planNodeId)
    {
        printStats(intent, planNodeId, false, false);
    }

    private void printStats(int indent, PlanNodeId planNodeId, boolean printInput, boolean printFiltered)
    {
        if (!this.stats.isPresent()) {
            return;
        }

        long totalMillis = this.stats.get().values().stream()
                .mapToLong(node -> node.getWallTime().toMillis())
                .sum();

        PlanNodeStats stats = this.stats.get().get(planNodeId);
        if (stats == null) {
            output.append(indentString(indent));
            output.append("Cost: ?");
            if (printInput) {
                output.append(", Input: ? (?B)");
            }
            output.append(", Output ? (?B)");
            if (printFiltered) {
                output.append(", Filtered: ?");
            }
            output.append('\n');
            return;
        }

        double fraction = (stats.getWallTime().toMillis()) / (double) totalMillis;
        if (isNaN(fraction)) {
            fraction = 0.0;
        }

        output.append(indentString(indent));
        output.append(format("Cost: %.2f%%", 100.0 * fraction));
        if (printInput) {
            output.append(format(", Input %d (%s)",
                    stats.getInputPositions(),
                    stats.getInputDataSize().toString()));
        }
        output.append(format(", Output %d (%s)",
                stats.getOutputPositions(),
                stats.getOutputDataSize().toString()));
        if (printFiltered) {
            double filtered = 100.0 * (stats.getInputPositions() - stats.getOutputPositions()) / stats.getInputPositions();
            if (isNaN(filtered)) {
                filtered = 0.0;
            }
            output.append(format(", Filtered: %.2f%%", filtered));
        }
        output.append('\n');
    }

    private static String indentString(int indent)
    {
        return Strings.repeat("    ", indent);
    }

    private class Visitor
            extends PlanVisitor<Integer, Void>
    {
        private final Map<Symbol, Type> types;
        private final Session session;

        @SuppressWarnings("AssignmentToCollectionOrArrayFieldFromParameter")
        public Visitor(Map<Symbol, Type> types, Session session)
        {
            this.types = types;
            this.session = session;
        }

        @Override
        public Void visitExplainAnalyze(ExplainAnalyzeNode node, Integer indent)
        {
            print(indent, "- ExplainAnalyze => [%s]", formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());
            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitJoin(JoinNode node, Integer indent)
        {
            List<Expression> joinExpressions = new ArrayList<>();
            for (JoinNode.EquiJoinClause clause : node.getCriteria()) {
                joinExpressions.add(new ComparisonExpression(ComparisonExpression.Type.EQUAL,
                        new QualifiedNameReference(clause.getLeft().toQualifiedName()),
                        new QualifiedNameReference(clause.getRight().toQualifiedName())));
            }

            print(indent, "- %s[%s] => [%s]", node.getType().getJoinLabel(), Joiner.on(" AND ").join(joinExpressions), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());
            node.getLeft().accept(this, indent + 1);
            node.getRight().accept(this, indent + 1);

            return null;
        }

        @Override
        public Void visitSemiJoin(SemiJoinNode node, Integer indent)
        {
            print(indent, "- SemiJoin[%s = %s] => [%s]", node.getSourceJoinSymbol(), node.getFilteringSourceJoinSymbol(), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());
            node.getSource().accept(this, indent + 1);
            node.getFilteringSource().accept(this, indent + 1);

            return null;
        }

        @Override
        public Void visitIndexSource(IndexSourceNode node, Integer indent)
        {
            print(indent, "- IndexSource[%s, lookup = %s] => [%s]", node.getIndexHandle(), node.getLookupSymbols(), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());
            for (Map.Entry<Symbol, ColumnHandle> entry : node.getAssignments().entrySet()) {
                if (node.getOutputSymbols().contains(entry.getKey())) {
                    print(indent + 2, "%s := %s", entry.getKey(), entry.getValue());
                }
            }
            return null;
        }

        @Override
        public Void visitIndexJoin(IndexJoinNode node, Integer indent)
        {
            List<Expression> joinExpressions = new ArrayList<>();
            for (IndexJoinNode.EquiJoinClause clause : node.getCriteria()) {
                joinExpressions.add(new ComparisonExpression(ComparisonExpression.Type.EQUAL,
                        new QualifiedNameReference(clause.getProbe().toQualifiedName()),
                        new QualifiedNameReference(clause.getIndex().toQualifiedName())));
            }

            print(indent, "- %sIndexJoin[%s] => [%s]", node.getType().getJoinLabel(), Joiner.on(" AND ").join(joinExpressions), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());
            node.getProbeSource().accept(this, indent + 1);
            node.getIndexSource().accept(this, indent + 1);

            return null;
        }

        @Override
        public Void visitLimit(LimitNode node, Integer indent)
        {
            print(indent, "- Limit[%s] => [%s]", node.getCount(), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());
            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitDistinctLimit(DistinctLimitNode node, Integer indent)
        {
            print(indent, "- DistinctLimit[%s] => [%s]", node.getLimit(), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());
            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitAggregation(AggregationNode node, Integer indent)
        {
            String type = "";
            if (node.getStep() != AggregationNode.Step.SINGLE) {
                type = format("(%s)", node.getStep().toString());
            }
            String key = "";
            if (!node.getGroupBy().isEmpty()) {
                key = node.getGroupBy().toString();
            }
            String sampleWeight = "";
            if (node.getSampleWeight().isPresent()) {
                sampleWeight = format("[sampleWeight = %s]", node.getSampleWeight().get());
            }

            print(indent, "- Aggregate%s%s%s => [%s]", type, key, sampleWeight, formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());

            for (Map.Entry<Symbol, FunctionCall> entry : node.getAggregations().entrySet()) {
                if (node.getMasks().containsKey(entry.getKey())) {
                    print(indent + 2, "%s := %s (mask = %s)", entry.getKey(), entry.getValue(), node.getMasks().get(entry.getKey()));
                }
                else {
                    print(indent + 2, "%s := %s", entry.getKey(), entry.getValue());
                }
            }

            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitMarkDistinct(MarkDistinctNode node, Integer indent)
        {
            print(indent, "- MarkDistinct[distinct=%s marker=%s] => [%s]", formatOutputs(node.getDistinctSymbols()), node.getMarkerSymbol(), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());
            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitWindow(WindowNode node, Integer indent)
        {
            List<String> partitionBy = Lists.transform(node.getPartitionBy(), Functions.toStringFunction());

            List<String> orderBy = Lists.transform(node.getOrderBy(), input -> input + " " + node.getOrderings().get(input));

            List<String> args = new ArrayList<>();
            if (!partitionBy.isEmpty()) {
                List<Symbol> prePartitioned = node.getPartitionBy().stream()
                        .filter(node.getPrePartitionedInputs()::contains)
                        .collect(toImmutableList());

                List<Symbol> notPrePartitioned = node.getPartitionBy().stream()
                        .filter(column -> !node.getPrePartitionedInputs().contains(column))
                        .collect(toImmutableList());

                StringBuilder builder = new StringBuilder();
                if (!prePartitioned.isEmpty()) {
                    builder.append("<")
                            .append(Joiner.on(", ").join(prePartitioned))
                            .append(">");
                    if (!notPrePartitioned.isEmpty()) {
                        builder.append(", ");
                    }
                }
                if (!notPrePartitioned.isEmpty()) {
                    builder.append(Joiner.on(", ").join(notPrePartitioned));
                }
                args.add(format("partition by (%s)", builder));
            }
            if (!orderBy.isEmpty()) {
                args.add(format("order by (%s)", Stream.concat(
                        node.getOrderBy().stream()
                                .limit(node.getPreSortedOrderPrefix())
                                .map(symbol -> "<" + symbol + ">"),
                        node.getOrderBy().stream()
                                .skip(node.getPreSortedOrderPrefix())
                                .map(Symbol::toString))
                        .collect(Collectors.joining(", "))));
            }

            print(indent, "- Window[%s] => [%s]", Joiner.on(", ").join(args), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());

            for (Map.Entry<Symbol, FunctionCall> entry : node.getWindowFunctions().entrySet()) {
                print(indent + 2, "%s := %s(%s)", entry.getKey(), entry.getValue().getName(), Joiner.on(", ").join(entry.getValue().getArguments()));
            }
            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitTopNRowNumber(TopNRowNumberNode node, Integer indent)
        {
            List<String> partitionBy = Lists.transform(node.getPartitionBy(), Functions.toStringFunction());

            List<String> orderBy = Lists.transform(node.getOrderBy(), input -> input + " " + node.getOrderings().get(input));

            List<String> args = new ArrayList<>();
            args.add(format("partition by (%s)", Joiner.on(", ").join(partitionBy)));
            args.add(format("order by (%s)", Joiner.on(", ").join(orderBy)));

            print(indent, "- TopNRowNumber[%s limit %s] => [%s]", Joiner.on(", ").join(args), node.getMaxRowCountPerPartition(), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());

            print(indent + 2, "%s := %s", node.getRowNumberSymbol(), "row_number()");
            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitRowNumber(RowNumberNode node, Integer indent)
        {
            List<String> partitionBy = Lists.transform(node.getPartitionBy(), Functions.toStringFunction());
            List<String> args = new ArrayList<>();
            if (!partitionBy.isEmpty()) {
                args.add(format("partition by (%s)", Joiner.on(", ").join(partitionBy)));
            }

            if (node.getMaxRowCountPerPartition().isPresent()) {
                args.add(format("limit = %s", node.getMaxRowCountPerPartition().get()));
            }

            print(indent, "- RowNumber[%s] => [%s]", Joiner.on(", ").join(args), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());

            print(indent + 2, "%s := %s", node.getRowNumberSymbol(), "row_number()");
            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitTableScan(TableScanNode node, Integer indent)
        {
            TableHandle table = node.getTable();
            print(indent, "- TableScan[%s, originalConstraint = %s] => [%s]", table, node.getOriginalConstraint(), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());
            printTableScanInfo(node, indent);

            return null;
        }

        @Override
        public Void visitValues(ValuesNode node, Integer indent)
        {
            print(indent, "- Values => [%s]", formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());
            for (List<Expression> row : node.getRows()) {
                print(indent + 2, "(" + Joiner.on(", ").join(row) + ")");
            }
            return null;
        }

        @Override
        public Void visitFilter(FilterNode node, Integer indent)
        {
            return visitScanFilterAndProjectInfo(node.getId(), Optional.of(node), Optional.empty(), indent);
        }

        @Override
        public Void visitProject(ProjectNode node, Integer indent)
        {
            if (node.getSource() instanceof FilterNode) {
                return visitScanFilterAndProjectInfo(node.getId(), Optional.of((FilterNode) node.getSource()), Optional.of(node), indent);
            }

            return visitScanFilterAndProjectInfo(node.getId(), Optional.empty(), Optional.of(node), indent);
        }

        private Void visitScanFilterAndProjectInfo(
                PlanNodeId planNodeId,
                Optional<FilterNode> filterNode, Optional<ProjectNode> projectNode,
                int indent)
        {
            checkState(projectNode.isPresent() || filterNode.isPresent());

            PlanNode sourceNode;
            if (filterNode.isPresent()) {
                sourceNode = filterNode.get().getSource();
            }
            else {
                sourceNode = projectNode.get().getSource();
            }

            Optional<TableScanNode> scanNode;
            if (sourceNode instanceof TableScanNode) {
                scanNode = Optional.of((TableScanNode) sourceNode);
            }
            else {
                scanNode = Optional.empty();
            }

            String format = "- ScanFilterAndProject[";
            List<Object> arguments = new LinkedList<>();

            if (scanNode.isPresent()) {
                format += "table = %s, originalConstraint = %s";
                if (filterNode.isPresent()) {
                    format += ", ";
                }
                TableHandle table = scanNode.get().getTable();
                arguments.add(table);
                arguments.add(scanNode.get().getOriginalConstraint());
            }

            if (filterNode.isPresent()) {
                format += "filterPredicate = %s";
                arguments.add(filterNode.get().getPredicate());
            }

            format += "] => [%s]";
            if (projectNode.isPresent()) {
                arguments.add(formatOutputs(projectNode.get().getOutputSymbols()));
            }
            else {
                arguments.add(formatOutputs(filterNode.get().getOutputSymbols()));
            }

            print(indent, format, arguments);
            printStats(indent + 2, planNodeId, true, true);

            if (projectNode.isPresent()) {
                printProjectInfo(projectNode.get(), indent);
            }

            if (scanNode.isPresent()) {
                printTableScanInfo(scanNode.get(), indent);
                return null;
            }

            sourceNode.accept(this, indent + 1);
            return null;
        }

        private void printProjectInfo(ProjectNode node, int indent)
        {
            for (Map.Entry<Symbol, Expression> entry : node.getAssignments().entrySet()) {
                if (entry.getValue() instanceof QualifiedNameReference && ((QualifiedNameReference) entry.getValue()).getName().equals(entry.getKey().toQualifiedName())) {
                    // skip identity assignments
                    continue;
                }
                print(indent + 2, "%s := %s", entry.getKey(), entry.getValue());
            }
        }

        private void printTableScanInfo(TableScanNode node, int indent)
        {
            TableHandle table = node.getTable();

            TupleDomain<ColumnHandle> predicate = node.getLayout()
                    .map(layoutHandle -> metadata.getLayout(session, layoutHandle))
                    .map(TableLayout::getPredicate)
                    .orElse(TupleDomain.<ColumnHandle>all());

            if (node.getLayout().isPresent()) {
                // TODO: find a better way to do this
                ConnectorTableLayoutHandle layout = node.getLayout().get().getConnectorHandle();
                if (!table.getConnectorHandle().toString().equals(layout.toString())) {
                    print(indent + 2, "LAYOUT: %s", layout);
                }
            }

            if (predicate.isNone()) {
                print(indent + 2, ":: NONE");
            }
            else {
                // first, print output columns and their constraints
                for (Map.Entry<Symbol, ColumnHandle> assignment : node.getAssignments().entrySet()) {
                    ColumnHandle column = assignment.getValue();
                    print(indent + 2, "%s := %s", assignment.getKey(), column);
                    printConstraint(indent + 3, column, predicate);
                }

                // then, print constraints for columns that are not in the output
                if (!predicate.isAll()) {
                    Set<ColumnHandle> outputs = ImmutableSet.copyOf(node.getAssignments().values());

                    predicate.getDomains().get()
                            .entrySet().stream()
                            .filter(entry -> !outputs.contains(entry.getKey()))
                            .forEach(entry -> {
                                ColumnHandle column = entry.getKey();
                                print(indent + 2, "%s", column);
                                printConstraint(indent + 3, column, predicate);
                            });
                }
            }
        }

        @Override
        public Void visitUnnest(UnnestNode node, Integer indent)
        {
            print(indent, "- Unnest [replicate=%s, unnest=%s] => [%s]", formatOutputs(node.getReplicateSymbols()), formatOutputs(node.getUnnestSymbols().keySet()), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());

            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitOutput(OutputNode node, Integer indent)
        {
            print(indent, "- Output[%s] => [%s]", Joiner.on(", ").join(node.getColumnNames()), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());
            for (int i = 0; i < node.getColumnNames().size(); i++) {
                String name = node.getColumnNames().get(i);
                Symbol symbol = node.getOutputSymbols().get(i);
                if (!name.equals(symbol.toString())) {
                    print(indent + 2, "%s := %s", name, symbol);
                }
            }

            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitTopN(TopNNode node, Integer indent)
        {
            Iterable<String> keys = Iterables.transform(node.getOrderBy(), input -> input + " " + node.getOrderings().get(input));

            print(indent, "- TopN[%s by (%s)] => [%s]", node.getCount(), Joiner.on(", ").join(keys), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());
            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitSort(SortNode node, Integer indent)
        {
            Iterable<String> keys = Iterables.transform(node.getOrderBy(), input -> input + " " + node.getOrderings().get(input));

            print(indent, "- Sort[%s] => [%s]", Joiner.on(", ").join(keys), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());
            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitRemoteSource(RemoteSourceNode node, Integer indent)
        {
            print(indent, "- RemoteSource[%s] => [%s]", Joiner.on(',').join(node.getSourceFragmentIds()), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());

            return null;
        }

        @Override
        public Void visitUnion(UnionNode node, Integer indent)
        {
            print(indent, "- Union => [%s]", formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());

            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitTableWriter(TableWriterNode node, Integer indent)
        {
            print(indent, "- TableWriter => [%s]", formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());
            for (int i = 0; i < node.getColumnNames().size(); i++) {
                String name = node.getColumnNames().get(i);
                Symbol symbol = node.getColumns().get(i);
                print(indent + 2, "%s := %s", name, symbol);
            }

            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitTableFinish(TableFinishNode node, Integer indent)
        {
            print(indent, "- TableCommit[%s] => [%s]", node.getTarget(), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());

            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitSample(SampleNode node, Integer indent)
        {
            print(indent, "- Sample[%s: %s] => [%s]", node.getSampleType(), node.getSampleRatio(), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());

            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitExchange(ExchangeNode node, Integer indent)
        {
            print(indent, "- Exchange[%s] => %s", node.getType(), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());

            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitDelete(DeleteNode node, Integer indent)
        {
            print(indent, "- Delete[%s] => [%s]", node.getTarget(), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());

            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitMetadataDelete(MetadataDeleteNode node, Integer indent)
        {
            print(indent, "- MetadataDelete[%s] => [%s]", node.getTarget(), formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());

            return processChildren(node, indent + 1);
        }

        @Override
        public Void visitEnforceSingleRow(EnforceSingleRowNode node, Integer indent)
        {
            print(indent, "- Scalar => [%s]", formatOutputs(node.getOutputSymbols()));
            printStats(indent + 2, node.getId());

            return processChildren(node, indent + 1);
        }

        @Override
        protected Void visitPlan(PlanNode node, Integer context)
        {
            throw new UnsupportedOperationException("not yet implemented: " + node.getClass().getName());
        }

        private Void processChildren(PlanNode node, int indent)
        {
            for (PlanNode child : node.getSources()) {
                child.accept(this, indent);
            }

            return null;
        }

        private String formatOutputs(Iterable<Symbol> symbols)
        {
            return Joiner.on(", ").join(Iterables.transform(symbols, input -> input + ":" + types.get(input)));
        }

        private void printConstraint(int indent, ColumnHandle column, TupleDomain<ColumnHandle> constraint)
        {
            checkArgument(!constraint.isNone());
            Map<ColumnHandle, Domain> domains = constraint.getDomains().get();
            if (!constraint.isAll() && domains.containsKey(column)) {
                print(indent, ":: %s", formatDomain(simplifyDomain(domains.get(column))));
            }
        }

        private String formatDomain(Domain domain)
        {
            ImmutableList.Builder<String> parts = ImmutableList.builder();

            if (domain.isNullAllowed()) {
                parts.add("NULL");
            }

            Type type = domain.getType();

            domain.getValues().getValuesProcessor().consume(
                    ranges -> {
                        for (Range range : ranges.getOrderedRanges()) {
                            StringBuilder builder = new StringBuilder();
                            if (range.isSingleValue()) {
                                String value = castToVarchar(type, range.getSingleValue());
                                builder.append('[').append(value).append(']');
                            }
                            else {
                                builder.append((range.getLow().getBound() == Marker.Bound.EXACTLY) ? '[' : '(');

                                if (range.getLow().isLowerUnbounded()) {
                                    builder.append("<min>");
                                }
                                else {
                                    builder.append(castToVarchar(type, range.getLow().getValue()));
                                }

                                builder.append(", ");

                                if (range.getHigh().isUpperUnbounded()) {
                                    builder.append("<max>");
                                }
                                else {
                                    builder.append(castToVarchar(type, range.getHigh().getValue()));
                                }

                                builder.append((range.getHigh().getBound() == Marker.Bound.EXACTLY) ? ']' : ')');
                            }
                            parts.add(builder.toString());
                        }
                    },
                    discreteValues -> discreteValues.getValues().stream()
                            .map(value -> castToVarchar(type, value))
                            .sorted() // Sort so the values will be printed in predictable order
                            .forEach(parts::add),
                    allOrNone -> {
                        if (allOrNone.isAll()) {
                            parts.add("ALL VALUES");
                        }
                    });

            return "[" + Joiner.on(", ").join(parts.build()) + "]";
        }

        private String castToVarchar(Type type, Object value)
        {
            Signature coercion = metadata.getFunctionRegistry().getCoercion(type, VARCHAR);
            MethodHandle method = metadata.getFunctionRegistry().getScalarFunctionImplementation(coercion).getMethodHandle();

            try {
                return ((Slice) method.invokeWithArguments(value)).toStringUtf8();
            }
            catch (OperatorNotFoundException e) {
                return "<UNREPRESENTABLE VALUE>";
            }
            catch (Throwable throwable) {
                throw Throwables.propagate(throwable);
            }
        }
    }

    private static class PlanNodeStats
    {
        private final PlanNodeId planNodeId;
        private final Duration wallTime;

        private final int inputOperatorId;
        private final long inputPositions;
        private final DataSize inputDataSize;

        private final int outputOperatorId;
        private final long outputPositions;
        private final DataSize outputDataSize;

        public PlanNodeStats(OperatorStats stats)
        {
            this(
                    stats.getPlanNodeId(),
                    new Duration(stats.getAddInputWall().toMillis() + stats.getGetOutputWall().toMillis() + stats.getFinishWall().toMillis(), MILLISECONDS),
                    stats.getOperatorId(),
                    stats.getInputPositions(),
                    stats.getInputDataSize(),
                    stats.getOperatorId(),
                    stats.getOutputPositions(),
                    stats.getOutputDataSize());
        }

        private PlanNodeStats(
                PlanNodeId planNodeId, Duration wallTime,
                int inputOperatorId, long inputPositions, DataSize inputDataSize,
                int outputOperatorId, long outputPositions, DataSize outputDataSize)
        {
            this.planNodeId = requireNonNull(planNodeId, "planNodeId is null");
            this.wallTime = requireNonNull(wallTime, "wallTime is null");

            this.inputOperatorId = inputOperatorId;
            this.inputPositions = inputPositions;
            this.inputDataSize = inputDataSize;

            this.outputOperatorId = outputOperatorId;
            this.outputPositions = outputPositions;
            this.outputDataSize = requireNonNull(outputDataSize, "outputDataSize is null");
        }

        public Duration getWallTime()
        {
            return wallTime;
        }

        public long getInputPositions()
        {
            return inputPositions;
        }

        public DataSize getInputDataSize()
        {
            return inputDataSize;
        }

        public long getOutputPositions()
        {
            return outputPositions;
        }

        public DataSize getOutputDataSize()
        {
            return outputDataSize;
        }

        public static PlanNodeStats merge(PlanNodeStats planNodeStats1, PlanNodeStats planNodeStats2)
        {
            checkArgument(planNodeStats1.planNodeId.equals(planNodeStats2.planNodeId), "planNodeIds do not match. %s != %s", planNodeStats1.planNodeId, planNodeStats2.planNodeId);

            final Duration duration = new Duration(planNodeStats1.getWallTime().toMillis() + planNodeStats2.getWallTime().toMillis(), MILLISECONDS);

            final int inputOperatorId;
            final long inputPositions;
            final DataSize inputDataSize;
            if (planNodeStats1.inputOperatorId < planNodeStats2.inputOperatorId) {
                inputOperatorId = planNodeStats1.inputOperatorId;
                inputPositions = planNodeStats1.inputPositions;
                inputDataSize = planNodeStats1.inputDataSize;
            }
            else if (planNodeStats1.inputOperatorId > planNodeStats2.inputOperatorId) {
                inputOperatorId = planNodeStats2.inputOperatorId;
                inputPositions = planNodeStats2.inputPositions;
                inputDataSize = planNodeStats2.inputDataSize;
            }
            else {
                inputOperatorId = planNodeStats1.inputOperatorId;
                inputPositions = planNodeStats1.inputPositions + planNodeStats2.inputPositions;
                inputDataSize = succinctBytes(planNodeStats1.inputDataSize.toBytes() + planNodeStats2.inputDataSize.toBytes());
            }

            final int outputOperatorId;
            final long outputPositions;
            final DataSize outputDataSize;
            if (planNodeStats1.outputOperatorId > planNodeStats2.outputOperatorId) {
                outputOperatorId = planNodeStats1.outputOperatorId;
                outputPositions = planNodeStats1.outputPositions;
                outputDataSize = planNodeStats1.outputDataSize;
            }
            else if (planNodeStats1.outputOperatorId < planNodeStats2.outputOperatorId) {
                outputOperatorId = planNodeStats2.outputOperatorId;
                outputPositions = planNodeStats2.outputPositions;
                outputDataSize = planNodeStats2.outputDataSize;
            }
            else {
                outputOperatorId = planNodeStats1.outputOperatorId;
                outputPositions = planNodeStats1.outputPositions + planNodeStats2.outputPositions;
                outputDataSize = succinctBytes(planNodeStats1.outputDataSize.toBytes() + planNodeStats2.outputDataSize.toBytes());
            }

            return new PlanNodeStats(
                    planNodeStats1.planNodeId, duration,
                    inputOperatorId, inputPositions, inputDataSize,
                    outputOperatorId, outputPositions, outputDataSize);
        }
    }
}
